import JSEncrypt from "jsencrypt";
import api from "./axios";

const PUBLIC_KEY_ENDPOINT = "/auth/public-key";
const ENCRYPTED_FIELDS = ["username", "email", "password"];

let publicKeyPromise = null;
let encryptorInstance = null;

async function fetchPublicKey() {
  if (!publicKeyPromise) {
    publicKeyPromise = api
      .get(PUBLIC_KEY_ENDPOINT)
      .then((response) => {
        const pem = response?.data?.public_key;
        if (!pem) {
          throw new Error("Public key missing from server response.");
        }
        return pem;
      })
      .catch((error) => {
        publicKeyPromise = null;
        throw error;
      });
  }
  return publicKeyPromise;
}

async function getEncryptor() {
  if (encryptorInstance) {
    return encryptorInstance;
  }

  const publicKeyPem = await fetchPublicKey();
  const encryptor = new JSEncrypt();
  encryptor.setPublicKey(publicKeyPem);

  encryptorInstance = encryptor;
  return encryptorInstance;
}

export async function prefetchEncryptionKey() {
  await getEncryptor();
}

export function resetEncryptionCache() {
  publicKeyPromise = null;
  encryptorInstance = null;
}

export async function encryptJsonPayload(payload) {
  const encryptor = await getEncryptor();
  const encryptedData = { ...payload };

  for (const field of ENCRYPTED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(payload, field)) {
      const value = payload[field];
      if (typeof value !== "string") {
        continue;
      }
      const encryptedValue = encryptor.encrypt(value);
      if (!encryptedValue) {
        resetEncryptionCache();
        throw new Error(`Failed to encrypt ${field}.`);
      }
      encryptedData[field] = encryptedValue;
    }
  }

  return encryptedData;
}
