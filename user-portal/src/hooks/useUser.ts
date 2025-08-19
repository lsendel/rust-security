import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '../lib/axios';
import { z } from 'zod';

// Basic SCIM User Schema
export const scimUserSchema = z.object({
  id: z.string(),
  userName: z.string(),
  name: z.object({
    givenName: z.string(),
    familyName: z.string(),
  }),
  emails: z.array(z.object({
    value: z.string().email(),
    primary: z.boolean(),
  })),
  active: z.boolean(),
  // Adding MFA status. The actual path in the SCIM response might be more complex.
  'urn:ietf:params:scim:schemas:extension:2.0:User:mfaEnabled': z.boolean().optional(),
});

export type ScimUser = z.infer<typeof scimUserSchema>;

const fetchUser = async (userId: string): Promise<ScimUser> => {
  const { data } = await axios.get(`/scim/v2/Users/${userId}`);
  return scimUserSchema.parse(data);
};

const updateUser = async ({ userId, userData }: { userId: string, userData: Partial<ScimUser> }) => {
  // SCIM uses PATCH for partial updates
  const { data } = await axios.patch(`/scim/v2/Users/${userId}`, {
    schemas: ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
    Operations: Object.entries(userData).map(([key, value]) => ({
      op: "replace",
      path: key, // This is a simplification, SCIM paths can be more complex
      value: value,
    })),
  });
  return data;
};

export const useUser = (userId: string) => {
  return useQuery<ScimUser, Error>(['user', userId], () => fetchUser(userId), {
    enabled: !!userId,
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation(updateUser, {
    onSuccess: (data) => {
      queryClient.invalidateQueries(['user', data.id]);
    },
  });
};
