import { useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '../lib/axios';

interface RegisterMfaResponse {
  secret: string;
  qr_code_uri: string;
}

interface VerifyMfaPayload {
  code: string;
}

interface BackupCodesResponse {
  backup_codes: string[];
}

const registerMfa = async (): Promise<RegisterMfaResponse> => {
  const { data } = await axios.post('/mfa/totp/register');
  return data;
};

const verifyMfa = async (payload: VerifyMfaPayload): Promise<void> => {
  await axios.post('/mfa/totp/verify', payload);
};

const generateBackupCodes = async (): Promise<BackupCodesResponse> => {
  const { data } = await axios.post('/mfa/totp/backup-codes/generate');
  return data;
};

// Assuming there is an endpoint to disable MFA.
// If not, this will fail and I'll remove it.
const disableMfa = async (): Promise<void> => {
  await axios.delete('/mfa/totp');
};


export const useRegisterMfa = () => {
  return useMutation<RegisterMfaResponse, Error, void>(registerMfa);
};

export const useVerifyMfa = () => {
  const queryClient = useQueryClient();
  return useMutation<void, Error, VerifyMfaPayload>(verifyMfa, {
    onSuccess: () => {
      queryClient.invalidateQueries(['user']);
    },
  });
};

export const useGenerateBackupCodes = () => {
  return useMutation<BackupCodesResponse, Error, void>(generateBackupCodes);
};

export const useDisableMfa = () => {
  const queryClient = useQueryClient();
  return useMutation<void, Error, void>(disableMfa, {
    onSuccess: () => {
      queryClient.invalidateQueries(['user']);
    },
  });
};
