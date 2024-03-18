import { NextApiRequest, NextApiResponse } from "next";
import type {
  JwtHeader,
  JwtPayload,
  SigningKeyCallback,
  VerifyErrors,
} from "jsonwebtoken";
import { verify } from "jsonwebtoken";
import jwks from "jwks-rsa";
import { z } from "zod";
import {env} from "~/env";

const jwksUri = "https://login.microsoftonline.com/common/discovery/keys";
const verifyOptions = {
  audience: env.AAD_CLIENT_ID,
  issuer: `https://sts.windows.net/${env.AAD_TENANT_ID}/`,
};

const getSigningKey = (header: JwtHeader, callback: SigningKeyCallback) => {
  const client = jwks({ jwksUri });
  client.getSigningKey(header.kid, (err, key) => {
    callback(null, key?.getPublicKey());
  });
};

const SubscriptionValidationEvent = z.object({
  validationCode: z.string().uuid(),
  validationUrl: z.string().url(),
});

const BlobCreated = z.object({
  api: z.literal("PutBlob"),
  requestId: z.string().uuid(),
  eTag: z.string(),
  contentType: z.string(),
  contentLength: z.number(),
  blobType: z.literal("BlockBlob"),
  url: z.string().url(),
  sequencer: z.string(),
  storageDiagnostics: z.object({
    batchId: z.string().uuid(),
  }),
});

const EventGridPayload = z
  .array(
    z.object({
      id: z.string().uuid(),
      topic: z.string(),
      subject: z.string(),
      data: z.union([SubscriptionValidationEvent, BlobCreated]),
      eventType: z.string(),
      eventTime: z.string().datetime(),
      metadataVersion: z.string(),
      dataVersion: z.string(),
    }),
  )
  .nonempty();

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  const { authorization } = req.headers;
  const token = authorization!.replace("Bearer ", "");

  try {
    await new Promise((resolve, reject) =>
      verify(
        token,
        getSigningKey,
        verifyOptions,
        (
          err: VerifyErrors | null,
          decoded: string | JwtPayload | undefined,
        ) => {
          if (err) {
            console.error("failed to verify.");
            reject(err);
          } else {
            console.info("succeeded to verify.");
            resolve(decoded);
          }
        },
      ),
    );

    const body = EventGridPayload.parse(req.body);
    const [event] = body;
    const { data } = event;

    const sve = SubscriptionValidationEvent.safeParse(data);
    if (sve.success) {
      const { validationCode } = sve.data;
      console.log({ validationCode });
      res.status(200).json({ validationResponse: validationCode });
    }

    const bc = BlobCreated.safeParse(data);
    if (bc.success) {
      const { url } = bc.data;
      console.log({ url });
      res.status(200).json({ url });
    }

    return res.status(400).json({ error: "Invalid event data" });
  } catch (error) {
    return res.status(401).json({ error });
  }
}
