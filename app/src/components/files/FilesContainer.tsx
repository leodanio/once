"use client";

import { useState } from "react";
import { FilesHero } from "@/components/files/FilesHero";
import { FileTransferCreator } from "@/components/files/FileTransferCreator";
import { FileRequestCreator } from "@/components/files/FileRequestCreator";
import { useApp } from "@/components/providers/AppProviders";
import { cn } from "@/lib/utils/cn";

export function FilesContainer() {
  const { t } = useApp();
  const [activeTab, setActiveTab] = useState<"send" | "request">("send");

  return (
    <div className="w-full max-w-2xl mx-auto px-4 py-8">
      <FilesHero />

      {/* Mode Switcher: INVIA | RICHIEDI */}
      <div className="flex justify-center mb-8">
        <div className="inline-flex p-1 rounded-lg border border-border bg-card/60 backdrop-blur-sm">
          <button
            type="button"
            onClick={() => setActiveTab("send")}
            className={cn(
              "px-5 py-2 text-xs font-semibold tracking-wider uppercase rounded-md transition-all",
              activeTab === "send"
                ? "bg-foreground text-background shadow-sm"
                : "text-foreground-muted hover:text-foreground"
            )}
          >
            {t.files.tabSend}
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("request")}
            className={cn(
              "px-5 py-2 text-xs font-semibold tracking-wider uppercase rounded-md transition-all",
              activeTab === "request"
                ? "bg-foreground text-background shadow-sm"
                : "text-foreground-muted hover:text-foreground"
            )}
          >
            {t.files.tabRequest}
          </button>
        </div>
      </div>

      {/* Active Tab Component */}
      <div className="transition-opacity duration-200">
        {activeTab === "send" ? <FileTransferCreator /> : <FileRequestCreator />}
      </div>
    </div>
  );
}
