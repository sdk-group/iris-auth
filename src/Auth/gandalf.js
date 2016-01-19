'use strict'

let jwt = require("jsonwebtoken");
let couchbird = require("Couchbird")();
let N1qlQuery = require("Couchbird").N1qlQuery;

let db_main = null;
let db_auth = null;
let default_expiration = false;
let jwt_secret = '667';
let name_cache = {};
let prop_mapping = {
	login: "iris://vocabulary/domain#login",
	password: "iris://vocabulary/domain#password",
	types: {
		'iris://vocabulary/domain#Employee': 'user',
		'iris://vocabulary/domain#AWP': 'device',
		'iris://vocabulary/domain#Terminal': 'device'
	}
};

class Gandalf {
	constructor() {
		throw new Error("Thou shall not instatiate this.");
	}
	static configure({
		data: b_main,
		session: b_auth,
		expiry: dexp
	}) {
		if(dexp) default_expiration = dexp;
		db_main = couchbird.bucket(b_main);
		db_auth = couchbird.bucket(b_auth);
	}

	static check({
		token: token
	}) {
		return Promise.promisify(jwt.verify)(token, jwt_secret)
			.then((decoded) => {
				return db_auth.get(`session::${decoded.user}::${decoded.origin}`);
			})
			.then((res) => {
				if(res.value && _.eq(token, res.value.token)) {
					return {
						value: true,
						data: res.value
					};
				} else {
					return {
						value: false,
						reason: 'Invalid token.'
					};
				}
			})
			.catch((err) => {
				return {
					value: false,
					reason: err.message
				};
			});
	}

	static authorize({
		user: user,
		password_hash: password_hash,
		origin: origin,
		expiry: expiry
	}) {
		let exp = expiry || default_expiration;
		let get_user = null;
		if(name_cache[user])
			get_user = db_main.get(name_cache[user]);
		else {
			let qstr = "SELECT * FROM `" + db_main.bucket_name + "` AS doc WHERE '" + prop_mapping.login + "' IN object_names(doc) ;";
			let query = N1qlQuery.fromString(qstr);
			get_user = db_main.N1QL(query)
				.then((res) => {
					let needle = false;
					_.map(res, (val) => {
						let value = val.doc;
						name_cache[value[prop_mapping.login][0]["@value"]] = value['@id'];
						if(_.eq(value[prop_mapping.login][0]["@value"], user))
							needle = value;
					});
					return needle;
				});
		}

		return get_user
			.then((res) => {
				if(!res) {
					return Promise.reject(new Error("No such user."));
				}
				let usr = res.cas ? res.value : res;
				if(!_.eq(usr[prop_mapping.password][0]["@value"], password_hash)) {
					return Promise.reject(new Error("Incorrect password."));
				}
				let type = prop_mapping.types[usr["@type"][0]] || 'none';
				let jwt_opts = {};
				if(!(exp === false)) {
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
					p_hash: password_hash,
					token: token
				};
				let db_opts = {};
				if(!(exp === false)) {
					db_opts = {
						"expiry": exp
					};
				}
				return db_auth.upsert(`session::${user}::${origin}`, data, db_opts)
					.then((res) => {
						return {
							value: true,
							token: token,
							data: data,
							cas: res.cas
						};
					});
			})
			.catch((err) => {
				return {
					value: false,
					reason: err.message
				};
			});
	}
	static update({
		token: token,
		expiry: expiry
	}) {
		let exp = expiry || default_expiration;
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
				if(!_.eq(token, res.value.token)) {
					Promise.reject(new Error('Invalid token.'));
				}
				data = res.value;
				data.last_seen = Date.now();
				let jwt_opts = {};
				if(!(exp === false)) {
					jwt_opts = {
						expiresIn: exp * 2
					};
				}
				data.token = jwt.sign(to_sign, jwt_secret, jwt_opts);
				let db_opts = {};
				if(!(exp === false)) {
					db_opts = {
						"expiry": exp
					};
				}
				return db_auth.upsert(`session::${to_sign.user}::${to_sign.origin}`, data, db_opts);
			})
			.then((res) => {
				return {
					value: true,
					token: data.token,
					cas: res.cas
				};
			})
			.catch((err) => {
				return {
					value: false,
					reason: err.message
				};
			});
	}
}

module.exports = Gandalf;