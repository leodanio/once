import { checkSecretMetadata } from "@/lib/secrets/service";
import { SecretReader } from "@/components/secrets/SecretReader";
import type { SecretMetadataResult } from "@/types/secret";

export const dynamic = "force-dynamic";
export const revalidate = 0;

interface SecretTokenPageProps {
  params: Promise<{ token: string }>;
}

export default async function SecretTokenPage({
  params,
}: SecretTokenPageProps) {
  const { token } = await params;

  // Non-consuming metadata check on page load: NEVER consumes the secret on GET.
  const metaOutcome = await checkSecretMetadata(token);

  const initialMetadata: SecretMetadataResult = metaOutcome.ok
    ? metaOutcome.metadata
    : {
        status: "available",
        passwordProtected: false,
        expiresAt: null,
      };

  return <SecretReader token={token} initialMetadata={initialMetadata} />;
}
