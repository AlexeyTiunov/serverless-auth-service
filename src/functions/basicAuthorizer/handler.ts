import * as process from "process";
import {
  APIGatewayAuthorizerResult,
  APIGatewayTokenAuthorizerEvent,
} from "aws-lambda/trigger/api-gateway-authorizer";

const generatePolicy = (
  principalId: string,
  resource: string,
  effect = "Allow"
): APIGatewayAuthorizerResult => {
  return {
    principalId,
    policyDocument: {
      Version: "2012-10-17",
      Statement: [
        {
          Action: "execute-api:Invoke",
          Effect: effect,
          Resource: resource,
        },
      ],
    },
  };
};

export const basicAuthorizer = async (
  event: APIGatewayTokenAuthorizerEvent
) => {
  console.log(event);
  const { type, authorizationToken, methodArn } = event;
  if (type !== "TOKEN") {
    return "Unauthorized";
  }
  try {
    const encodedCreds = authorizationToken.split(" ")[1];
    const buff: Buffer = Buffer.from(encodedCreds, "base64");
    const plainCreds: Array<string> = buff.toString("utf-8").split(":");
    const [userName, password] = plainCreds;

    if (!process.env[userName])
      return generatePolicy(authorizationToken, methodArn, "Deny");

    const effect: string =
      process.env[userName] === password ? "Allow" : "Deny";

    return generatePolicy(userName, methodArn, effect);
  } catch {
    return generatePolicy(authorizationToken, methodArn, "Deny");
  }
};
