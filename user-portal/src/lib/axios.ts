import axios from 'axios';

const axiosInstance = axios.create({
  baseURL: 'http://localhost:8080',
  withCredentials: true,
});

// Attach CSRF header from csrf_token cookie for state-changing requests
axiosInstance.interceptors.request.use(
  (config) => {
    const method = (config.method || 'get').toLowerCase();
    const unsafe = ['post', 'put', 'patch', 'delete'].includes(method);
    if (unsafe) {
      const csrf = document.cookie
        .split(';')
        .map((s) => s.trim())
        .find((kv) => kv.startsWith('csrf_token='))?.split('=')[1];
      if (csrf) {
        config.headers = config.headers || {};
        (config.headers as any)['X-CSRF-Token'] = csrf;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

export default axiosInstance;
