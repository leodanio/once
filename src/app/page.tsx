import { Header } from "@/components/layout/Header";
import { Footer } from "@/components/layout/Footer";
import { SecretsHero } from "@/components/secrets/SecretsHero";
import { SecretCreator } from "@/components/secrets/SecretCreator";

export default function HomePage() {
  return (
    <>
      <Header />
      <main
        tabIndex={-1}
        className="flex-1 flex flex-col items-center justify-center w-full max-w-2xl mx-auto px-6 py-12 focus:outline-none"
      >
        <div className="w-full">
          <SecretsHero />
          <SecretCreator />
        </div>
      </main>
      <Footer />
    </>
  );
}
