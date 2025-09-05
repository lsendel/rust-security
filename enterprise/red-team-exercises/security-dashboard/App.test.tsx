import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthContext } from './src/contexts/AuthContext';

// Mock the AuthContext with minimal required values
const mockAuthContext = {
  currentUser: { id: 'test-user', email: 'test@test.com', role: 'user', permissions: [] },
  isAuthenticated: true,
  login: vi.fn(),
  logout: vi.fn(),
  refreshToken: vi.fn(),
  getAuthToken: vi.fn().mockResolvedValue('mock-token')
};

import App from './src/App';

describe('App', () => {
  it('renders without crashing', () => {
    const queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });

    const { container } = render(
      <AuthContext.Provider value={mockAuthContext}>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            <App />
          </BrowserRouter>
        </QueryClientProvider>
      </AuthContext.Provider>
    );
    expect(container).toBeTruthy();
  });
});
