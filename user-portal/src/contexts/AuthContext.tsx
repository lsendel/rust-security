import React,
{
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from 'react';
import axios from 'axios';

interface AuthContextType {
  isAuthenticated: boolean;
  user: any;
  login: () => void;
  logout: () => void;
  handleAuthentication: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const AUTH_SERVICE_BASE_URL = 'http://localhost:8080';
const CLIENT_ID = 'user-portal';
const REDIRECT_URI = 'http://localhost:3000/callback';

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [user, setUser] = useState<any>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    const storedToken = localStorage.getItem('authToken');
    if (storedToken) {
      setToken(storedToken);
      setIsAuthenticated(true);
      // In a real app, you'd also fetch user info here
    }
  }, []);

  const generateRandomString = (length: number) => {
    const array = new Uint32Array(length / 2);
    window.crypto.getRandomValues(array);
    return Array.from(array, (dec) => ('0' + dec.toString(16)).substr(-2)).join('');
  };

  const sha256 = async (plain: string) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(plain);
    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return hash;
  };

  const base64urlencode = (a: ArrayBuffer) => {
    return btoa(String.fromCharCode.apply(null, new Uint8Array(a)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  };

  const login = async () => {
    const codeVerifier = generateRandomString(64);
    localStorage.setItem('codeVerifier', codeVerifier);

    const codeChallenge = await sha256(codeVerifier);
    const codeChallengeBase64 = base64urlencode(codeChallenge);

    const authUrl = new URL(`${AUTH_SERVICE_BASE_URL}/oauth/authorize`);
    authUrl.searchParams.append('response_type', 'code');
    authUrl.searchParams.append('client_id', CLIENT_ID);
    authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
    authUrl.searchParams.append('scope', 'openid profile email');
    authUrl.searchParams.append('code_challenge', codeChallengeBase64);
    authUrl.searchParams.append('code_challenge_method', 'S256');
    authUrl.searchParams.append('state', generateRandomString(32));

    window.location.href = authUrl.toString();
  };

  const logout = () => {
    setIsAuthenticated(false);
    setUser(null);
    setToken(null);
    localStorage.removeItem('authToken');
    localStorage.removeItem('refreshToken');
    // In a real app, you would also call the /oauth/revoke endpoint
    window.location.href = '/';
  };

  const handleAuthentication = async () => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const codeVerifier = localStorage.getItem('codeVerifier');

    if (!code || !codeVerifier) {
      return;
    }

    try {
      const response = await axios.post(
        `${AUTH_SERVICE_BASE_URL}/oauth/token`,
        new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier: codeVerifier,
        }),
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );

      const { access_token, refresh_token } = response.data;
      setToken(access_token);
      localStorage.setItem('authToken', access_token);
      if (refresh_token) {
        localStorage.setItem('refreshToken', refresh_token);
      }
      setIsAuthenticated(true);

      // Fetch user info
      const userinfoResponse = await axios.get(`${AUTH_SERVICE_BASE_URL}/oauth/userinfo`, {
        headers: { Authorization: `Bearer ${access_token}` },
      });
      setUser(userinfoResponse.data);

    } catch (error) {
      console.error('Error exchanging authorization code for token:', error);
    } finally {
      localStorage.removeItem('codeVerifier');
    }
  };


  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout, handleAuthentication }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
