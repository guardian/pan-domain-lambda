Custom lambda authenticator using pan-domain for API Gateway.

### Custom authorizer

This lambda is meant to be used as a custom authorizer in AWS API GateWay.

It requires the `method.request.header.Cookie` **Identity token source** and is compatible with [pan-domain-authentication](https://github.com/guardian/pan-domain-authentication).

Documentation on custom authorizers can be found [here](https://aws.amazon.com/blogs/compute/introducing-custom-authorizers-in-amazon-api-gateway/) and [here](http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html).

### Output

The lambda's output looks like

```
{
  "principalId": "FirstName LastName <email@domain.co.uk>",
  "policyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "execute-api:Invoke",
        "Effect": "Allow|Deny",
        "Resource": "arn:full-arn-of-the-requested-api"
      }
    ]
  }
}
```
