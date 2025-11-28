# Mantissa Log Web Interface

React-based web interface for Mantissa Log security monitoring platform.

## Prerequisites

- Node.js >= 18.0.0
- npm or yarn

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure environment variables:

```bash
cp .env.example .env
```

Edit `.env` and add your AWS configuration:

- `VITE_COGNITO_USER_POOL_ID`: Your Cognito User Pool ID
- `VITE_COGNITO_CLIENT_ID`: Your Cognito App Client ID
- `VITE_API_ENDPOINT`: Your API Gateway endpoint
- `VITE_AWS_REGION`: AWS region (e.g., us-east-1)

Get these values from your Terraform outputs:

```bash
cd ../
cat terraform-outputs.json | jq -r '{
  user_pool_id: .user_pool_id.value,
  client_id: .user_pool_client_id.value,
  api_endpoint: .api_endpoint.value
}'
```

3. Start development server:

```bash
npm run dev
```

The application will be available at `http://localhost:3000`

## Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run preview` - Preview production build
- `npm run lint` - Run ESLint
- `npm run format` - Format code with Prettier

## Project Structure

```
web/
├── src/
│   ├── components/      # Reusable UI components
│   │   └── Layout/      # Layout components (Sidebar, Header)
│   ├── pages/           # Page components
│   ├── stores/          # Zustand state stores
│   ├── services/        # API services
│   ├── hooks/           # Custom React hooks
│   ├── utils/           # Utility functions
│   ├── config/          # Configuration files
│   ├── styles/          # Global styles
│   ├── App.jsx          # Root component with routing
│   └── main.jsx         # Application entry point
├── public/              # Static assets
├── index.html           # HTML template
├── package.json         # Dependencies and scripts
├── vite.config.js       # Vite configuration
└── tailwind.config.js   # Tailwind CSS configuration
```

## Building for Production

```bash
npm run build
```

The production build will be in the `dist/` directory.

## Deployment

The web interface can be deployed to:

- AWS S3 + CloudFront
- Vercel
- Netlify
- Any static hosting service

### Deploy to S3 + CloudFront

```bash
# Build the application
npm run build

# Upload to S3
aws s3 sync dist/ s3://your-bucket-name --delete

# Invalidate CloudFront cache
aws cloudfront create-invalidation \
  --distribution-id YOUR_DISTRIBUTION_ID \
  --paths "/*"
```

## Features

- Authentication via AWS Cognito
- Natural language query interface
- Detection rules management
- Alert dashboard
- Real-time data visualization
- Dark/light mode support
- Responsive design

## Technology Stack

- React 18
- Vite (build tool)
- React Router (routing)
- TanStack Query (data fetching)
- Zustand (state management)
- Tailwind CSS (styling)
- Headless UI (accessible components)
- AWS Amplify (authentication)
- Recharts (data visualization)

## Development Guidelines

### Code Style

- Use functional components with hooks
- Use Tailwind CSS for styling
- Follow React best practices
- Keep components small and focused
- Use TypeScript types where appropriate

### Component Structure

```jsx
import { useState } from 'react'
import clsx from 'clsx'

export default function MyComponent({ prop1, prop2 }) {
  const [state, setState] = useState(null)

  const handleAction = () => {
    // Handler logic
  }

  return (
    <div className={clsx('base-classes', prop1 && 'conditional-class')}>
      {/* Component content */}
    </div>
  )
}
```

### API Integration

Use the API service layer for all backend calls:

```javascript
import { apiClient } from '../services/api'

const data = await apiClient.get('/endpoint')
```

### State Management

- Use Zustand for global state
- Use React Query for server state
- Use local state (useState) for UI state

## Troubleshooting

### Authentication Issues

If you see authentication errors:

1. Verify Cognito configuration in `.env`
2. Check that user pool and app client exist
3. Ensure API endpoint is correct
4. Clear browser cache and local storage

### Build Failures

If the build fails:

1. Delete `node_modules` and `package-lock.json`
2. Run `npm install` again
3. Ensure Node.js version >= 18.0.0
4. Check for TypeScript/ESLint errors

### API Connection Issues

If the app can't connect to the API:

1. Verify `VITE_API_ENDPOINT` in `.env`
2. Check CORS configuration on API Gateway
3. Ensure Cognito user has proper permissions
4. Check browser console for errors
