const tap = require('tap');
const lambda = require('../tmp/lambda/index');
const EventEmitter = require('events');

class EmitterError extends EventEmitter {
	constructor () {
		super();
		process.nextTick(() => this.emit('error', 'emitting an error'));
	}
}
class EmitterInvalid extends EventEmitter {
	constructor () {
		super();
		this.statusCode = 403;
		process.nextTick(() => {
			this.emit('data', '<Error><Message>XML error</Message></Error>');
			this.emit('end');
		});
	}
}
class EmitterResponse extends EventEmitter {
	constructor () {
		super();
		this.statusCode = 200;
		process.nextTick(() => {
			this.emit('data', 'publicKey=abcde');
			this.emit('end');
		});
	}
}
const cryptoInvalid = {
	createVerify () {
		return {
			update () {
				return {
					verify () { return false; }
				};
			}
		};
	}
};
const cryptoValid = {
	createVerify () {
		return {
			update () {
				return {
					verify () { return true; }
				};
			}
		};
	}
};
function cookie (data) {
	return 'gutoolsAuth-assym=' + (new Buffer(data, 'utf8')).toString('base64') + '.signature';
}

tap.test('fails when fetching a key emits an error', test => {
	test.plan(3);

	lambda.handleEvents({
		events: {},
		https: {
			get (path, callback) {
				callback(new EmitterError());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.equal(err.message, 'emitting an error');
			}
		},
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails when fetching a key return invalid response', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: {},
		https: {
			get (path, callback) {
				callback(new EmitterInvalid());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.equal(err.message, 'XML error');
			}
		},
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails when the cookie is missing', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: {},
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /missing authorization/i);
			}
		},
		crypto: cryptoInvalid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating the signature', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: 'token' },
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /invalid authorization/i);
			}
		},
		crypto: cryptoInvalid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating an expired cookie', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: cookie('expires=Thu May 26 2016 16:00:00 GMT') },
		now: new Date('Thu May 26 2016 17:00:00 GMT'),
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /authorisation has expired/i);
			}
		},
		crypto: cryptoValid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating an invalid date', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: cookie('expires=') },
		now: new Date('Thu May 26 2016 17:00:00 GMT'),
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /authorisation has expired/i);
			}
		},
		crypto: cryptoValid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating an invalid user email', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: cookie('expires=Thu May 26 2016 18:00:00 GMT&email=someone@gmail.com') },
		now: new Date('Thu May 26 2016 17:00:00 GMT'),
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /valid guardian user/i);
			}
		},
		crypto: cryptoValid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('fails validating an multifactor is disabled', function (test) {
	test.plan(3);

	lambda.handleEvents({
		events: { authorizationToken: cookie('expires=Thu May 26 2016 18:00:00 GMT&email=someone@guardian.co.uk') },
		now: new Date('Thu May 26 2016 17:00:00 GMT'),
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error (err) {
				test.type(err, Error);
				test.match(err.message, /2FA turned on/i);
			}
		},
		crypto: cryptoValid,
		callback: (err, policy) => {
			test.equal(policy.policyDocument.Statement[0].Effect, 'Deny');
			test.end();
		}
	});
});

tap.test('validates the user correctly', function (test) {
	test.plan(2);

	lambda.handleEvents({
		events: { authorizationToken: cookie([
			'expires=Thu May 26 2016 18:00:00 GMT',
			'email=someone@guardian.co.uk',
			'multifactor=true',
			'firstName=Jon',
			'lastName=Doe'
		].join('&')) },
		now: new Date('Thu May 26 2016 17:00:00 GMT'),
		https: {
			get (path, callback) {
				callback(new EmitterResponse());
			}
		},
		logger: {
			log () {},
			error () {}
		},
		crypto: cryptoValid,
		callback: (err, policy) => {
			test.equal(policy.principalId, 'Jon Doe <someone@guardian.co.uk>');
			test.equal(policy.policyDocument.Statement[0].Effect, 'Allow');
			test.end();
		}
	});
});
