import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import QRCode from 'qrcode.react';
import { useAuth } from '../contexts/AuthContext';
import { useUser } from '../hooks/useUser';
import { useRegisterMfa, useVerifyMfa, useGenerateBackupCodes, useDisableMfa } from '../hooks/useMfa';

const verifyMfaSchema = z.object({
  code: z.string().length(6, 'Code must be 6 digits'),
});
type VerifyMfaFormData = z.infer<typeof verifyMfaSchema>;

const SecurityPage = () => {
  const { user: authUser } = useAuth();
  const { data: scimUser, isLoading: isLoadingUser } = useUser(authUser?.sub);
  const registerMfa = useRegisterMfa();
  const verifyMfa = useVerifyMfa();
  const generateBackupCodes = useGenerateBackupCodes();
  const disableMfa = useDisableMfa();

  const [qrCodeUri, setQrCodeUri] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);

  const { register, handleSubmit, formState: { errors } } = useForm<VerifyMfaFormData>({
    resolver: zodResolver(verifyMfaSchema),
  });

  const handleRegister = async () => {
    const data = await registerMfa.mutateAsync();
    setQrCodeUri(data.qr_code_uri);
    setSecret(data.secret);
  };

  const handleVerify = async (data: VerifyMfaFormData) => {
    await verifyMfa.mutateAsync({ code: data.code });
    setQrCodeUri(null);
    setSecret(null);
  };

  const handleGenerateBackupCodes = async () => {
    const data = await generateBackupCodes.mutateAsync();
    setBackupCodes(data.backup_codes);
  };

  const mfaEnabled = scimUser?.['urn:ietf:params:scim:schemas:extension:2.0:User:mfaEnabled'];

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Security</h1>
      <div className="p-4 border rounded-md bg-white">
        <h2 className="text-xl font-semibold">Multi-Factor Authentication (MFA)</h2>
        {isLoadingUser ? (
          <p>Loading MFA status...</p>
        ) : (
          <>
            <p className="mb-4">
              MFA Status: <span className={mfaEnabled ? 'font-bold text-green-600' : 'font-bold text-red-600'}>
                {mfaEnabled ? 'Enabled' : 'Disabled'}
              </span>
            </p>
            {!mfaEnabled && !qrCodeUri && (
              <button onClick={handleRegister} className="bg-blue-500 text-white py-2 px-4 rounded">
                Enable MFA
              </button>
            )}
            {qrCodeUri && secret && (
              <div className="mt-4 p-4 border rounded-md">
                <h3 className="text-lg font-semibold">Set up your authenticator app</h3>
                <p>1. Scan this QR code with your authenticator app (e.g., Google Authenticator, Authy).</p>
                <div className="my-4">
                  <QRCode value={qrCodeUri} size={256} />
                </div>
                <p>2. If you can't scan the QR code, you can manually enter this secret:</p>
                <p className="font-mono bg-gray-100 p-2 rounded my-2">{secret}</p>
                <p>3. Enter the 6-digit code from your app to verify and complete the setup.</p>
                <form onSubmit={handleSubmit(handleVerify)} className="flex items-center space-x-2 mt-4">
                  <input {...register('code')} className="border p-2 rounded" placeholder="6-digit code" />
                  <button type="submit" className="bg-green-500 text-white py-2 px-4 rounded">Verify</button>
                </form>
                {errors.code && <p className="text-red-500 mt-2">{errors.code.message}</p>}
              </div>
            )}
            {mfaEnabled && (
              <div className="space-y-4">
                <button onClick={handleGenerateBackupCodes} className="bg-gray-500 text-white py-2 px-4 rounded">
                  Generate Backup Codes
                </button>
                <button onClick={() => disableMfa.mutate()} className="bg-red-500 text-white py-2 px-4 rounded ml-4">
                  Disable MFA
                </button>
                {backupCodes && (
                  <div className="mt-4 p-4 border rounded-md bg-yellow-50">
                    <h3 className="text-lg font-semibold">Your Backup Codes</h3>
                    <p>Store these codes in a safe place. They can be used to access your account if you lose your device.</p>
                    <ul className="list-disc list-inside my-2">
                      {backupCodes.map(code => <li key={code} className="font-mono">{code}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
};

export default SecurityPage;
