import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { FileRequestGuestUploader } from "@/components/files/FileRequestGuestUploader";

export const dynamic = "force-dynamic";
export const revalidate = 0;

interface FileRequestPageProps {
  params: Promise<{ token: string }>;
}

export default async function FileRequestPage({ params }: FileRequestPageProps) {
  const { token } = await params;

  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-12 focus:outline-none"
      >
        <FileRequestGuestUploader token={token} />
      </main>
      <Footer />
    </>
  );
}
