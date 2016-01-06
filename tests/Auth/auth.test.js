let auth = require("./index");
let RDFcb = require("cbird-rdf").LD;
let Couchbird = require("Couchbird");
let cfg = {
	"name": "main",
	"couchbird": {
		"server_ip": "127.0.0.1",
		"n1ql": "127.0.0.1:8093"
	},
	"buckets": {
		"main": "rdf",
		"auth": "ss",
		"history": "rdf"
	},
	"vocabulary": {
		"basic": "iris://vocabulary/basic",
		"domain": "iris://vocabulary/domain",
		"fs": false
	}
};

auth.configure({
	data: cfg.buckets.main,
	session: cfg.buckets.auth
});

describe("Auth", () => {

	let m_bucket = null;
	let a_bucket = null;
	let db = null;
	let port = 3000;
	let token = null;

	let user_data = [{
		"@id": "iris://data#human-2",
		"@type": [
			"iris://vocabulary/domain#Employee"
		],
		"iris://vocabulary/domain#firstName": [{
			"@language": "en",
			"@value": "Maria"
		}],
		"iris://vocabulary/domain#hasSchedule": [{
			"@id": "iris://data#schedule-2"
		}],
		"iris://vocabulary/domain#lastName": [{
			"@language": "en",
			"@value": "Medvedeva"
		}],
		"iris://vocabulary/domain#login": [{
			"@language": "en",
			"@value": "masha"
		}],
		"iris://vocabulary/domain#middleName": [{
			"@language": "en",
			"@value": "Ivanovna"
		}],
		"iris://vocabulary/domain#password": [{
			"@value": "654321"
		}],
		"iris://vocabulary/domain#provides": [{
			"@id": "iris://data#service-2"
		}]
	}, {
		"@id": "iris://data#human-1",
		"@type": [
			"iris://vocabulary/domain#Employee"
		],
		"iris://vocabulary/domain#firstName": [{
			"@language": "en",
			"@value": "Vasily"
		}],
		"iris://vocabulary/domain#hasSchedule": [{
			"@id": "iris://data#schedule-1"
		}],
		"iris://vocabulary/domain#lastName": [{
			"@language": "en",
			"@value": "Ivanov"
		}],
		"iris://vocabulary/domain#login": [{
			"@language": "en",
			"@value": "JohnDee"
		}],
		"iris://vocabulary/domain#middleName": [{
			"@language": "en",
			"@value": "Ivanovich"
		}],
		"iris://vocabulary/domain#password": [{
			"@value": "123456"
		}],
		"iris://vocabulary/domain#provides": [{
			"@id": "iris://data#service-2"
		}, {
			"@id": "iris://data#service-1"
		}]
	}];

	before((done) => {
		db = new RDFcb(cfg.couchbird);
		a_bucket = db.bucket(cfg.buckets.auth);
		m_bucket = db.bucket(cfg.buckets.main);
		m_bucket.upsertNodes(user_data);
		m_bucket.N1QL(Couchbird.N1qlQuery.fromString("CREATE PRIMARY INDEX ON " + cfg.buckets.main + ";"))
			.then(done.bind(null, null), done);
	});

	describe("construction", () => {
		it("shall not be constructed", () => {
			expect(auth).to.throw(Error);
		})
	})
	describe("auth success", () => {
		it("shall pass", (done) => {
			auth.authorize({
					user: "JohnDee",
					password_hash: "123456",
					address: "London"
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.true;
					expect(res).to.have.property("token").which.is.not.undefined;
					expect(res).to.have.property("cas").which.is.not.undefined;
					token = res.token;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
	})
	describe("auth fail", () => {
		it("shall not pass : wrong password", (done) => {
			auth.authorize({
					user: "JohnDee",
					password_hash: "1234567",
					address: "London"
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.false;
					expect(res).to.have.property("reason").which.is.equal("Incorrect password.");
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
		it("shall not pass : wrong username", (done) => {
			auth.authorize({
					user: "JohnDoe",
					password_hash: "123456",
					address: "London"
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.false;
					expect(res).to.have.property("reason").which.is.equal("No such user.");
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
	});
	describe("check session", () => {
		it("shall pass", (done) => {
			auth.check({
					token: token,
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.true;
					expect(res).to.have.property("data").which.is.Object;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
		it("shall not pass", (done) => {
			auth.check({
					token: "1",
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.false;
					expect(res).to.have.property("reason").which.is.not.empty;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
	});
	describe("update session", () => {
		it("should update token", (done) => {
			auth.update({
					token: token,
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.true;
					expect(res).to.have.property("token").which.is.not.undefined;
					expect(res).to.have.property("cas").which.is.not.undefined;
					token = res.token;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
		it("should reject session update", (done) => {
			auth.update({
					token: "1",
				})
				.then((res) => {
					expect(res).to.have.property("value").which.is.false;
					expect(res).to.have.property("reason").which.is.not.empty;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
	});
	describe("create system session", () => {
		it('should create an eternal session', (done) => {
			auth.authorize({
					user: "webwidget",
					password_hash: "123456",
					address: "",
					expiry: false
				})
				.then((res) => {
					// console.log(res);
					expect(res).to.have.property("value").which.is.true;
					expect(res).to.have.property("token").which.is.not.undefined;
					expect(res).to.have.property("cas").which.is.not.undefined;
					token = res.token;
					done();
				})
				.catch((err) => {
					done(err);
				});
		});
	});
});