'use strict';

const _ = require("lodash"),
	os = require("os"),
	path = require("path"),
	Promise = require("bluebird"),
	fs = Promise.promisifyAll(require("fs")),
	homedir = require("homedir"),
	crypto = require("crypto"),
	MongoPortable = require("mongo-portable").MongoPortable,
	FileSystemStore = require("file-system-store").FileSystemStore,
	mkdirpAsync = Promise.promisify(require("mkdirp"));

module.exports.create = function (options) {

	const defaults = {
		path: path.join(homedir(), "le-store")
	};
	const mergedOptions = _.defaults(options, defaults);
	const db = new MongoPortable(path.basename(mergedOptions.path));

	db.addStore(new FileSystemStore({
		// The path where the database will be stored
		ddbb_path: path.dirname(path.resolve(mergedOptions.path)),
		// Whether the persistance will be asynchronous or not
		sync: true
	}));

	var accounts = {

		// Accounts
		setKeypair: function (opts, keypair, cb) {
			// opts.email		 // optional
			// opts.accountId // optional - same as returned from acounts.set(opts, reg)

			// SAVE to db (as PEM and/or JWK) and index each domain in domains to this keypair
			// keypair = { privateKeyPem: '...', privateKeyJwk: { ... } }
			const doc = _.defaults(opts, {
				keypair: keypair
			});

			const query = {$or: []};
			if (opts.email) {
				query["$or"].push({email: opts.email});
			}
			if (opts.accountId) {
				query["$or"].push({email: opts.accountId});
			}

			//console.log("account.setKeypair", doc);
			db.collection("accounts")
			.update(query, doc, {upsert: true}, (err) => {
				if (err) return cb(err);
				cb(null, keypair);
			});
		},
		// Accounts
		checkKeypair: function (opts, cb) {
			// opts.email // optional
			// opts.accountId // optional - same as returned from acounts.set(opts, reg)

			// check db and return null or keypair object with one
			// (or both) of privateKeyPem or privateKeyJwk
			//console.log("account.checkKeypair", opts);
			db.collection("accounts")
			.find(opts, (err, results) => {
				if (err) cb(err)
				else if (results && results.length === 1) cb(null, results[0].keypair)
				else if (results && results.length > 1) cb(null, results)
				else cb(null, null);
			});
			//cb(null, { privateKeyPem: '...', privateKeyJwk: {} });
		},

		// Accounts
		check: function (opts, cb) {
			// opts.email			 // optional
			// opts.accountId	 // optional - same as returned from acounts.set(opts, reg)
			// opts.domains		 // optional - same as set in certificates.set(opts, certs)

			const search = _.cloneDeep(opts);

			if (opts.domains && opts.domains[0]) {
				delete search.domains;
				search["domains.0"] = opts.domains[0];
			}

			// return account from db if it exists, otherwise null
			//console.log("check", search);
			db.collection("accounts")
			.find(search, (err, results) => {
				//console.log("accounts.check (result)", result);
				if (err) cb(err)
				else if (results && results.length === 1) cb(null, results[0])
				else if (results && results.length > 1) cb(null, results)
				else cb(null, null);
			});
			//cb(null, { id: '...', keypair: { privateKeyJwk: {} }/*, domains: []*/ });
		},
		// Accounts
		set: function (opts, reg, cb) {
			// opts.email
			// reg.keypair
			// reg.receipt // response from acme server


			// You must implement a method to deterministically generate 'id'
			// For example, you could do this:
			delete opts.id;
			delete opts.accountId;
			const id = crypto.createHash('sha256').update(reg.keypair.publicKeyPem).digest('hex');
			//cb(null, { id: '...', email: opts.email, keypair: reg.keypair, receipt: reg.receipt });
			const doc = _.extend(opts, reg, {
				id: id,
				accountId: id
			});
			//console.log("set", opts, reg);
			db.collection("accounts")
			.update({email: doc.email}, doc, {updateAsMongo: false, override: true}, (err) => {
				if (err) return cb(err);
				//console.log("set (result)", doc);
				cb(null, doc);
			});
		}
	};

	var certificates = {

		// Certificates
		setKeypair: function (opts, keypair, cb) {
			// opts.domains - this is an array, but you nly need the first (or any) of them
			// SAVE to db (as PEM and/or JWK) and index each domain in domains to this keypair
			const query = {
				"domains.0": opts.domains[0]
			};
			console.log("setKeypair", opts, keypair);
			db.collection("certificates")
			.update(opts, _.defaults(opts, {certs: keypair}), {upsert: true}, () => {
				if (err) return cb(err);
				cb(null, keypair);
			});
			//cb(null, keypair);
		},
		// Certificates
		checkKeypair: function (opts, cb) {
			// opts.domains - this is an array, but you only need the first (or any) of them
			
			const search = _.cloneDeep(opts);

			if (opts.domains && opts.domains[0]) {
				delete search.domains;
				search["domains.0"] = opts.domains[0];
			}

			// return account from db if it exists, otherwise null
			db.collection("certificates")
			.find(search, (err, results) => {
				if (err) cb(err)
				else if (results && results.length === 1) {
					cb(null, _.omit(_.extend({}, results[0], results[0].certs), "certs"))
				}
				else if (results && results.length > 1) cb(null, results)
				else cb(null, null);
			});

			// check db and return null or keypair object with one of privateKeyPem or privateKeyJwk
			//cb(null, { privateKeyPem: '...', privateKeyJwk: {} });
		},

		// Certificates
		check: function (opts, cb) {
			// You will be provided one of these (which should be tried in this order)
			// opts.domains
			// opts.email // optional
			// opts.accountId // optional

			const search = _.cloneDeep(opts);

			if (opts.domains && opts.domains[0]) {
				delete search.domains;
				search["domains"] = opts.domains[0];
			}

			// return account from db if it exists, otherwise null
			db.collection("certificates")
			.find(search, (err, results) => {
				if (err) cb(err)
				else if (results && results.length === 1) {
					cb(null, _.omit(_.extend({}, results[0], results[0].certs), "certs"))
				}
				else if (results && results.length > 1) cb(null, results)
				else cb(null, null);
			});

			// return certificate PEMs from db if they exist, otherwise null
			// optionally include expiresAt and issuedAt, if they are known exactly
			// (otherwise they will be read from the cert itself later)
			//cb(null, { privkey: 'PEM', cert: 'PEM', chain: 'PEM', domains: [], accountId: '...' });
		},
		// Certificates
		set: function (opts, pems, cb) {
			// opts.domains	 // each of these must be indexed
			// opts.email		 // optional, should be indexed
			// opts.accountId // optional - same as set by you in accounts.set(opts, keypair) above

			// pems.privkey
			// pems.cert
			// pems.chain
			
			const search = _.cloneDeep(opts);

			if (opts.domains && opts.domains[0]) {
				delete search.domains;
				search["domains.0"] = opts.domains[0];
			}

			//console.log("certificates.set", opts, pems);
			//console.log("set", opts, pems);
			const doc = _.defaults(opts, {certs: pems});
			db.collection("certificates")
			.update(search, doc, {upsert: true}, (err) => {
				if (err) return cb(err);
				//console.log("certificates.set (result)", doc);
				cb(null, doc);
			});

			// SAVE to the database, index the email address, the accountId, and alias the domains
			//cb(null, pems);
		}

	};

	return {
		getOptions: function () {
			// merge options with default settings and then return them
			return mergedOptions;
		},
		accounts: accounts,
		certificates: certificates
	};
};
