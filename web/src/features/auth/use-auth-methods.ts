import { useQuery } from '@tanstack/react-query'
import { authApi } from '@/api/client'
import type { AuthMethod } from '@/api/types'

export function useAuthMethods(returnTo?: string) {
  return useQuery<AuthMethod[]>({
    queryKey: ['auth', 'methods', returnTo ?? ''],
    queryFn: () => authApi.getMethods(returnTo),
  })
}

export function useAuthCapabilities(returnTo?: string) {
  const { data: methods, ...rest } = useAuthMethods(returnTo)

  const hasOAuth = methods?.some(m => m.methodType === 'OAUTH_REDIRECT') ?? false
  const registrationEnabled = methods?.some(m => m.methodType === 'REGISTRATION') ?? false
  const passwordResetEnabled = methods?.some(m => m.methodType === 'PASSWORD_RESET') ?? false

  return {
    methods,
    hasOAuth,
    registrationEnabled,
    passwordResetEnabled,
    ...rest,
  }
}
