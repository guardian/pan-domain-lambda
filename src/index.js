import {parse as parseCookies} from 'cookie';
import httpsModule from 'https';
import {getPEM} from 'pan-domain-public-keys';
import validateUser from 'pan-domain-validate-user';
import {STAGE} from './environment';

export function handler (events, context, callback) {
	handleEvents({events, callback, https: httpsModule, logger: console, validate: validateUser});
}

export function handleEvents ({events, callback, https, logger, validate}) {
	const cookie = getPandaCookie(events.authorizationToken || '');

	getPEM(STAGE, https)
	.then(key => validate(cookie, key))
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

function getPandaCookie (data) {
	const cookies = parseCookies(data);
	return cookies['gutoolsAuth-assym'] || '';
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
