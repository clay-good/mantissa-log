import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Amplify } from 'aws-amplify'
import { Toaster } from 'react-hot-toast'
import App from './App'
import { awsConfig } from './config/aws-config'
import { ThemeProvider } from './context/ThemeContext'
import { ConversationProvider } from './context/ConversationContext'
import './styles/globals.css'

Amplify.configure(awsConfig)

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
      staleTime: 5 * 60 * 1000,
    },
  },
})

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ThemeProvider>
      <ConversationProvider>
        <BrowserRouter>
          <QueryClientProvider client={queryClient}>
            <App />
            <Toaster
              position="top-right"
              toastOptions={{
                className: 'bg-white dark:bg-mono-900 text-mono-950 dark:text-mono-50 border border-mono-200 dark:border-mono-800',
                duration: 4000,
              }}
            />
          </QueryClientProvider>
        </BrowserRouter>
      </ConversationProvider>
    </ThemeProvider>
  </React.StrictMode>
)
