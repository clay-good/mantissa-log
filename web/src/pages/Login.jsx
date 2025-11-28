import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../stores/authStore'
import toast from 'react-hot-toast'

export default function Login() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const { login, isAuthenticated } = useAuthStore()
  const navigate = useNavigate()

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/')
    }
  }, [isAuthenticated, navigate])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)

    const result = await login(email, password)

    if (result.success) {
      toast.success('Login successful')
      navigate('/')
    } else {
      toast.error(result.error || 'Login failed')
    }

    setIsLoading(false)
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-mono-50 dark:bg-mono-950 px-4 transition-colors">
      <div className="w-full max-w-md">
        <div className="text-center animate-fade-in">
          <h1 className="text-3xl font-bold text-mono-950 dark:text-mono-50">Mantissa Log</h1>
          <p className="mt-2 text-sm text-mono-600 dark:text-mono-400">
            Separate the Signal from the Noise
          </p>
        </div>

        <form onSubmit={handleSubmit} className="mt-8 space-y-6 animate-slide-up">
          <div className="bg-white dark:bg-mono-900 rounded-lg p-6 border border-mono-200 dark:border-mono-800 shadow-lg">
            <div className="space-y-4">
              <div>
                <label
                  htmlFor="email"
                  className="block text-sm font-medium text-mono-900 dark:text-mono-100"
                >
                  Email address
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-500 focus:outline-none focus:ring-2 focus:ring-mono-900 dark:focus:ring-mono-100 transition-all"
                  placeholder="you@example.com"
                />
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-mono-900 dark:text-mono-100"
                >
                  Password
                </label>
                <input
                  id="password"
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-white dark:bg-mono-950 border border-mono-300 dark:border-mono-700 rounded-lg text-mono-900 dark:text-mono-50 placeholder-mono-500 focus:outline-none focus:ring-2 focus:ring-mono-900 dark:focus:ring-mono-100 transition-all"
                  placeholder="••••••••"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="mt-6 w-full px-4 py-2 bg-mono-950 dark:bg-mono-50 text-mono-50 dark:text-mono-950 rounded-lg font-medium hover:bg-mono-800 dark:hover:bg-mono-200 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
            >
              {isLoading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
