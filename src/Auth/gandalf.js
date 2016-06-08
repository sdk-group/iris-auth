'use strict'

let jwt = require("jsonwebtoken");
let couchbird = require("Couchbird")();

let db_main = null;
let db_auth = null;
let default_expiration = false;
let jwt_secret = '667';
let prop_mapping = {
	login: "login",
	password: "password_hash"
};
let users = {};
class Gandalf {
	constructor() {
		throw new Error("Thou shall not instatiate this.");
	}
	static configure({
		data: b_main,
		session: b_auth,
		expiry: dexp,
		property_mapping: props
	}) {
		if (dexp) default_expiration = dexp;
		if (_.isPlainObject(props)) prop_mapping = _.merge(prop_mapping, props);
		db_main = couchbird.bucket(b_main);
		db_auth = couchbird.bucket(b_auth);
	}

	static check({
		token
	}) {
		// console.log("CHECKING TOKEN", token);
		db_auth.reconnect();
		db_main.reconnect();

		return Promise.promisify(jwt.verify)(token, jwt_secret)
			.then((decoded) => {
				// console.log("DECODED", decoded);
				return db_auth.get(`session::${decoded.user}::${decoded.origin}`);
			})
			.then((res) => {
				if (res.value && _.isEqual(token, res.value.token)) {
					return {
						state: true,
						value: res.value
					};
				} else {
					return {
						state: false,
						reason: 'Invalid token.'
					};
				}
			})
			.catch((err) => {
				global.logger && logger.error(err, "Auth::check error");
				return {
					state: false,
					reason: err.message
				};
			});
	}

	static authorize({
		user,
		password_hash,
		origin,
		expiry
	}) {
		db_auth.reconnect();
		db_main.reconnect();
		let exp = (expiry == false) ? false : expiry || default_expiration;
		let usr;
		let cached = inmemory_cache.get('global_membership_description');
		return (cached ? Promise.resolve(cached) : db_main.get('global_membership_description')
				.then(res => res.value.content))
			.then(res => {
				let keys = _.map(res, 'member');
				// console.log("MISSING", rest);
				return db_main.getMulti(keys);
			})
			.then(users => {
				// console.log("USERS GOT", res);
				let res = _.find(users, (val) => (val.value.login == user || val.login == user));
				if (!res) {
					return Promise.reject(new Error("No such user."));
				}
				usr = res.value || res;
				if (!_.isEqual(usr[prop_mapping.password], password_hash)) {
					return Promise.reject(new Error("Incorrect password."));
				}
				return db_auth.get(`session::${user}::${origin}`)
					.catch(err => {
						return {};
					});
			})
			.then((res) => {
				// console.log("EXISTS", res, user, origin, exp);
				if (res.value && exp === false) {
					return {
						state: true,
						value: res.value,
						cas: res.cas
					};
				} else {
					let type = usr["@type"] || 'none';
					let jwt_opts = {};
					if (!(exp === false)) {
						jwt_opts = {
							expiresIn: exp * 2
						};
					}
					let token = jwt.sign({
						user: user,
						origin: origin
					}, jwt_secret, jwt_opts);

					let data = {
						login: user,
						first_seen: Date.now(),
						last_seen: Date.now(),
						origin: origin,
						user_id: usr["@id"],
						user_type: type,
						p_hash: password_hash,
						token
					};
					let db_opts = {};
					if (!(exp === false)) {
						db_opts = {
							"expiry": exp
						};
					}
					return db_auth.upsert(`session::${user}::${origin}`, data, db_opts)
						.then((res) => {
							return {
								state: true,
								value: data,
								cas: res.cas
							};
						});
				}
			})
			.catch((err) => {
				// console.log("AUTH ERR", err.stack);
				global.logger && logger.error(err, "Auth::authorize error");
				return {
					state: false,
					reason: err.message
				};
			});
	}
	static update({
		token,
		expiry
	}) {
		let exp = (expiry == false) ? false : expiry || default_expiration;
		let to_sign = {};
		let data = null;
		return Promise.promisify(jwt.verify)(token, jwt_secret)
			.then((decoded) => {
				to_sign = {
					user: decoded.user,
					origin: decoded.origin
				};
				return db_auth.get(`session::${decoded.user}::${decoded.origin}`);
			})
			.then((res) => {
				if (!_.isEqual(token, res.value.token)) {
					Promise.reject(new Error('Invalid token.'));
				}
				data = res.value;
				data.last_seen = Date.now();
				let jwt_opts = {};
				if (!(exp === false)) {
					jwt_opts = {
						expiresIn: exp * 2
					};
				}
				data.token = jwt.sign(to_sign, jwt_secret, jwt_opts);
				let db_opts = {};
				if (!(exp === false)) {
					db_opts = {
						"expiry": exp
					};
				}
				return db_auth.upsert(`session::${to_sign.user}::${to_sign.origin}`, data, db_opts);
			})
			.then((res) => {
				return {
					state: true,
					token: data.token,
					cas: res.cas
				};
			})
			.catch((err) => {
				global.logger && logger.error(err, "Auth::update error");
				return {
					state: false,
					reason: err.message
				};
			});
	}
}

module.exports = Gandalf;