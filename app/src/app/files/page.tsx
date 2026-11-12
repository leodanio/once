import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { FilesContainer } from "@/components/files/FilesContainer";

export default function FilesPage() {
  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-8 focus:outline-none"
      >
        <FilesContainer />
      </main>
      <Footer />
    </>
  );
}
