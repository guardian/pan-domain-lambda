import {parse as parseCookies} from 'cookie';
import {guardianValidation, PanDomainAuthentication} from '@guardian/pan-domain-node'; 
import {SETTINGS_FILE, REGION} from './environment';

export function handler (events, context, callback) {
	const panda = new PanDomainAuthentication('gutoolsAuth-assym', REGION, 'pan-domain-auth-settings', SETTINGS_FILE, guardianValidation);
	handleEvents({events, callback, panda, logger: console});
}

export function handleEvents ({events, callback, panda, logger}) {
	console.log(events.authorizationToken || '');
	const cookie = getPandaCookie(events.authorizationToken || '');

	panda.verify(cookie)
	.then(({ status, user }) => {
		if (status === 'Authorised') {
			callback(null, policy(
				`${user.firstName} ${user.lastName} <${user.email}>`,
				'Allow',
				events.methodArn
			));
		} else {
			throw new Error('Authorisation failed ' + status);
		}
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
