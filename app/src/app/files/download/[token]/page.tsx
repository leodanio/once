import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { FileDownloader } from "@/components/files/FileDownloader";

export const dynamic = "force-dynamic";
export const revalidate = 0;

interface FileDownloadPageProps {
  params: Promise<{ token: string }>;
}

export default async function FileDownloadPage({ params }: FileDownloadPageProps) {
  const { token } = await params;

  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-12 focus:outline-none"
      >
        <FileDownloader token={token} />
      </main>
      <Footer />
    </>
  );
}
