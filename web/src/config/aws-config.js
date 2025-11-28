export const awsConfig = {
  Auth: {
    Cognito: {
      userPoolId: import.meta.env.VITE_COGNITO_USER_POOL_ID || '',
      userPoolClientId: import.meta.env.VITE_COGNITO_CLIENT_ID || '',
      loginWith: {
        email: true,
      },
    },
  },
  API: {
    REST: {
      mantissalog: {
        endpoint: import.meta.env.VITE_API_ENDPOINT || '',
        region: import.meta.env.VITE_AWS_REGION || 'us-east-1',
      },
    },
  },
}

export const appConfig = {
  apiEndpoint: import.meta.env.VITE_API_ENDPOINT || '',
  region: import.meta.env.VITE_AWS_REGION || 'us-east-1',
}
