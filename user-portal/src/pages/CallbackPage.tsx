import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const CallbackPage = () => {
  const { handleAuthentication } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const processAuth = async () => {
      await handleAuthentication();
      navigate('/');
    };
    processAuth();
  }, [handleAuthentication, navigate]);

  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center">
        <h1 className="text-2xl font-bold">Authenticating...</h1>
        <p>Please wait while we log you in.</p>
      </div>
    </div>
  );
};

export default CallbackPage;
