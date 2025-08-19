import React, { useState, useEffect } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { useAuth } from '../contexts/AuthContext';
import { useUser, useUpdateUser, scimUserSchema } from '../hooks/useUser';

const profileFormSchema = scimUserSchema.pick({
  name: true,
  emails: true,
});

type ProfileFormData = z.infer<typeof profileFormSchema>;

const ProfilePage = () => {
  const { user: authUser } = useAuth();
  const { data: scimUser, isLoading, isError } = useUser(authUser?.sub);
  const updateUser = useUpdateUser();
  const [isEditing, setIsEditing] = useState(false);

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<ProfileFormData>({
    resolver: zodResolver(profileFormSchema),
  });

  useEffect(() => {
    if (scimUser) {
      reset({
        name: scimUser.name,
        emails: scimUser.emails,
      });
    }
  }, [scimUser, reset]);

  const onSubmit = async (data: ProfileFormData) => {
    if (!authUser?.sub) return;

    // A more sophisticated implementation would calculate the patch operations
    // based on what has changed. For now, we'll just send the name object.
    const patchData = {
        name: data.name,
        emails: data.emails,
    }

    await updateUser.mutateAsync({ userId: authUser.sub, userData: patchData });
    setIsEditing(false);
  };

  if (isLoading) return <div>Loading profile...</div>;
  if (isError) return <div>Error loading profile.</div>;
  if (!scimUser) return <div>No profile data found.</div>;

  return (
    <div>
      <h1 className="text-2xl font-bold mb-4">Profile</h1>
      {!isEditing ? (
        <div className="space-y-4">
          <div>
            <label className="font-semibold">Username:</label>
            <p>{scimUser.userName}</p>
          </div>
          <div>
            <label className="font-semibold">First Name:</label>
            <p>{scimUser.name.givenName}</p>
          </div>
          <div>
            <label className="font-semibold">Last Name:</label>
            <p>{scimUser.name.familyName}</p>
          </div>
          <div>
            <label className="font-semibold">Primary Email:</label>
            <p>{scimUser.emails.find(e => e.primary)?.value}</p>
          </div>
          <button
            onClick={() => setIsEditing(true)}
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded"
          >
            Edit Profile
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label htmlFor="givenName" className="font-semibold">First Name</label>
            <input id="givenName" {...register('name.givenName')} className="border p-2 rounded w-full" />
            {errors.name?.givenName && <p className="text-red-500">{errors.name.givenName.message}</p>}
          </div>
          <div>
            <label htmlFor="familyName" className="font-semibold">Last Name</label>
            <input id="familyName" {...register('name.familyName')} className="border p-2 rounded w-full" />
            {errors.name?.familyName && <p className="text-red-500">{errors.name.familyName.message}</p>}
          </div>
           <div>
            <label htmlFor="email" className="font-semibold">Primary Email</label>
            <input id="email" {...register('emails.0.value')} className="border p-2 rounded w-full" />
            {errors.emails?.[0]?.value && <p className="text-red-500">{errors.emails[0].value.message}</p>}
          </div>
          <div className="flex space-x-2">
            <button
              type="submit"
              disabled={isSubmitting}
              className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded"
            >
              {isSubmitting ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              onClick={() => setIsEditing(false)}
              className="bg-gray-500 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded"
            >
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default ProfilePage;
