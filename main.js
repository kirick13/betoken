
const BISON         = require('@kirick/bison');
const RedisClient   = require('@kirick/redis-client/src/client.js');
const Snowflake     = require('@kirick/snowflake');
const base62        = require('base-x')('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ');
const { evilcrypt } = require('evilcrypt');
const LRU           = require('lru-cache');

const unixtime = (ms) => Math.floor((ms ?? Date.now()) / 1000);

const REDIS_PREFIX = '@betoken:';

class BEToken {
	constructor (
		redisClient,
		lru,
		snowflake,
		{
			namespace,
			versions,
		} = {},
	) {
		if (redisClient instanceof RedisClient !== true) {
			throw new TypeError('Argument redisClient must be an instance of RedisClient from package "@kirick/redis-client"');
		}
		this._redisClient = redisClient;

		if (lru instanceof LRU !== true) {
			throw new TypeError('Argument lru must be an instance of LRU from package "lru-cache"');
		}
		this._lru = lru;

		if (snowflake instanceof Snowflake !== true) {
			throw new TypeError('Argument snowflake must be an instance of Snowflake from package "@kirick/snowflake"');
		}
		this._snowflake = snowflake;

		this._redis_keys = {
			revoked: `${REDIS_PREFIX}${namespace}:revoked`,
		};

		this._version_actual = null;
		this._versions = [];
		for (const { encryption_key, args } of versions) {
			const data = {
				encryption_key,
				args,
			};

			if (!this._version_actual) {
				this._version_actual = data;
			}

			this._versions.push(data);
		}
	}

	async create (
		data,
		{ ttl },
	) {
		const version = this._version_actual;

		const id_buffer = this._snowflake.create();
		const ts_expire = unixtime() + ttl;

		const payload = [
			id_buffer,
			ts_expire,
		];

		for (const key of version.args) {
			const value = data[key];

			if (undefined === value) {
				throw new TypeError(`Invalid value given for key "${key}".`);
			}

			payload.push(value);
		}

		const payload_buffer = BISON.encode(payload);

		const token_buffer = await evilcrypt.encrypt(
			Buffer.from(payload_buffer),
			version.encryption_key,
		);

		return base62.encode(token_buffer);
	}

	async parse (
		token,
		{
			unsafe = false,
		} = {},
	) {
		const is_cached = this._lru.has(token);
		let data;

		if (is_cached) {
			data = this._lru.get(token);
		}
		else {
			let payload_buffer;
			let version_args;
			for (const { encryption_key, args } of this._versions) {
				try {
					const token_buffer = base62.decode(token);

					payload_buffer = await evilcrypt.decrypt(
						token_buffer,
						encryption_key,
					);

					version_args = args;

					break;
				}
				catch {}
			}

			if (!payload_buffer) {
				const error = new Error('Cannot decode token by given versions.');
				error.code = 'BETOKEN.INVALID_VERSION';

				throw error;
			}

			const payload = BISON.decode(payload_buffer);

			const [
				id_arraybuffer,
				ts_expire,
			] = payload;

			const id_buffer = Buffer.from(id_arraybuffer);

			const id_data = this._snowflake.parse(id_buffer);

			data = {
				_id: id_buffer,
				_ts_created: unixtime(id_data.ts),
				_ts_expire: ts_expire,
			};

			for (const [ index, key ] of version_args.entries()) {
				let value = payload[index + 2];
				if (value instanceof ArrayBuffer) {
					value = Buffer.from(value);
				}

				data[key] = value;
			}
		}

		if (data.ts_expire < unixtime()) {
			const error = new Error('Token has expired.');
			error.code = 'BETOKEN.EXPIRED';

			throw error;
		}

		if (true !== unsafe) {
			const [ score ] = await this._redisClient.MULTI()
				.ZSCORE(
					this._redis_keys.revoked,
					data._id.toString('base64'),
				)
				.ZREMRANGEBYSCORE(
					this._redis_keys.revoked,
					'-inf',
					unixtime(),
				)
			.EXEC();

			if (null !== score) {
				const error = new Error('Token has been revoked.');
				error.code = 'BETOKEN.REVOKED';

				throw error;
			}
		}

		if (!is_cached) {
			this._lru.set(
				token,
				data,
			);
		}

		return data;
	}

	async revoke (token) {
		try {
			const {
				_id,
				_ts_expire,
			} = await this.parse(
				token,
				{
					unsafe: true,
				},
			);

			await this._redisClient.ZADD(
				this._redis_keys.revoked,
				_ts_expire,
				_id.toString('base64'),
			);
		}
		catch (error) {
			if (error?.code?.startsWith('BETOKEN.') !== true) {
				throw error;
			}
		}
	}
}

module.exports = BEToken;
