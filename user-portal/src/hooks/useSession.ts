import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from '../lib/axios';
import { useAuth } from '../contexts/AuthContext';

interface IntrospectionResult {
  active: boolean;
  scope: string;
  client_id: string;
  exp: number;
  iat: number;
}

const introspectToken = async (token: string): Promise<IntrospectionResult> => {
  const { data } = await axios.post('/oauth/introspect', new URLSearchParams({ token }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
  return data;
};

const revokeToken = async (token: string) => {
  await axios.post('/oauth/revoke', new URLSearchParams({ token }), {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
  });
};

export const useCurrentSession = () => {
  const token = localStorage.getItem('authToken');
  return useQuery<IntrospectionResult, Error>(
    ['session', token],
    () => introspectToken(token!),
    { enabled: !!token }
  );
};

export const useRevokeSession = () => {
  const { logout } = useAuth();
  const queryClient = useQueryClient();

  return useMutation<void, Error, string>(revokeToken, {
    onSuccess: (_, token) => {
      queryClient.invalidateQueries(['session', token]);
      // After revoking the token, we need to log the user out from the client-side as well.
      logout();
    },
  });
};
