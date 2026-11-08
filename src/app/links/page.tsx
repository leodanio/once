import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { Hero } from "@/components/home/Hero";
import { LinkCreator } from "@/components/home/LinkCreator";

export default function LinksPage() {
  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-12 focus:outline-none"
      >
        <div className="w-full">
          <Hero />
          <LinkCreator />
        </div>
      </main>
      <Footer />
    </>
  );
}
