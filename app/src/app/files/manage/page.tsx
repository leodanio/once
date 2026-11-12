import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { FileRequestManager } from "@/components/files/FileRequestManager";

export const dynamic = "force-dynamic";
export const revalidate = 0;

export default function FileManagePage() {
  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-12 focus:outline-none"
      >
        <FileRequestManager />
      </main>
      <Footer />
    </>
  );
}
