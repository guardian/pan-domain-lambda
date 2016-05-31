import cryptoModule from 'crypto';
import {parse as parseCookies} from 'cookie';
import httpsModule from 'https';
import {parse as parseQueryString} from 'querystring';
import {base64toPEM} from 'format-pem-keys';
import {STAGE} from './environment';

export function handler (events, context, callback) {
	handleEvents({events, callback, https: httpsModule, logger: console,
		crypto: cryptoModule, now: new Date()});
}

export function handleEvents ({events, callback, https, logger, crypto, now}) {
	fetchPublicKey({https, path: publicKeyPath(STAGE), logger})
	.then(key => extractUserFromCookie(events.authorizationToken, key, crypto))
	.then(user => validateUser(user, now))
	.then(user => {
		callback(null, policy(
			`${user.firstName} ${user.lastName} <${user.email}>`,
			'Allow',
			events.methodArn
		));
	})
	.catch(ex => {
		logger.error(ex);
		callback(null, policy('', 'Deny', events.methodArn));
	});
}

function publicKeyPath (stage) {
	return 'https://s3-eu-west-1.amazonaws.com/pan-domain-auth-settings/' + (stage === 'PROD' ?
		'gutools.co.uk.settings.public' :
		(stage.toLowerCase()  + '.dev-gutools.co.uk.settings.public')
	);
}

function fetchPublicKey ({https, path, logger}) {
	logger.log('Getting public key from ', path);
	return new Promise ((resolve, reject) => {
		https.get(path, res => {
			const data = [];
			res.on('data', chunk => data.push(chunk.toString('utf8')));
			res.on('end', () => {
				const responseText = data.join('');
				if (res.statusCode === 200) {
					resolve(responseText.replace(/^publicKey=/i, ''));
				} else {
					// Response might be xml
					const match = responseText.match(/<message>(.*)<\/message>/i);
					const error = new Error(match ? match[1] : 'Invalid public key response');
					error.responseText = responseText;
					reject(error);
				}
			});
			res.on('error', error => reject(new Error(error)));
		});
	});
}

function extractUserFromCookie (data, publicKey, crypto) {
	return new Promise((resolve, reject) => {
		if (data) {
			const pem = base64toPEM(publicKey);
			const [message, signature] = getPandaCookie(data);

			if (verifySignature(message, signature, pem, crypto)) {
				resolve(parseQueryString(message));
			} else {
				reject(new Error('Invalid authorization token signature'));
			}
		} else {
			reject(new Error('Missing authorization token'));
		}
	});
}

function getPandaCookie (data) {
	const cookies = parseCookies(data);
	const pandaAsymm = cookies['gutoolsAuth-assym'] || '';
	const message = decodeBase64(pandaAsymm.slice(0, pandaAsymm.lastIndexOf('.')));
	const signature = pandaAsymm.slice(pandaAsymm.lastIndexOf('.') + 1);
	return [message, signature];
}

function validateUser (user, now) {
	const expires = new Date(user.expires);
	if (!isValidDate(expires) || expires < now) {
		return Promise.reject(new Error('User authorisation has expired'));
	}
	if (!isGuardianUser(user)) {
		return Promise.reject(new Error('User is not a valid Guardian user'));
	}
	if (!has2FAEnabled(user)) {
		return Promise.reject(new Error('User doesn\'t have 2FA turned on'));
	}
	return user;
}

function isValidDate (date) {
	return !isNaN(date.getTime());
}

function isGuardianUser (user) {
	return (user.email || '').indexOf('guardian.co.uk') !== -1;
}

function has2FAEnabled (user) {
	return user.multifactor === 'true';
}

function decodeBase64 (data) {
	return (new Buffer(data, 'base64')).toString('utf8');
}

function verifySignature (message, signature, pandaPublicKey, crypto) {
	return crypto.createVerify('sha256WithRSAEncryption')
        .update(message, 'utf-8')
        .verify(pandaPublicKey, signature, 'base64');
}

function policy (principal, effect, arn) {
	return {
		principalId: principal,
		policyDocument: {
			Version: '2012-10-17',
			Statement: [{
				Action: 'execute-api:Invoke',
				Effect: effect,
				Resource: arn
			}]
		}
	};
}
