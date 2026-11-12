import type { ExpirationPreset } from "@/types/link";
import type {
  SlugValidationErrorCode,
  UrlValidationErrorCode,
} from "@/lib/utils/url";
import type { CreateLinkErrorCode } from "@/lib/links/service";

export type Locale = "en" | "it";

export interface Dictionary {
  meta: {
    homeAriaLabel: string;
    headerNavAriaLabel: string;
    footerNavAriaLabel: string;
    links: string;
    secrets: string;
    files: string;
    about: string;
    github: string;
    switchThemeToLight: string;
    switchThemeToDark: string;
    languageSelectorAriaLabel: string;
  };
  hero: {
    title: string;
    subtitle: string;
  };
  secrets: {
    title: string;
    subtitle: string;
    messageLabel: string;
    messagePlaceholder: string;
    clearMessageAriaLabel: string;
    expirationLabel: string;
    passwordLabel: string;
    passwordOptionalBadge: string;
    passwordActiveBadge: string;
    passwordPlaceholder: string;
    passwordSecurityHint: string;
    showPasswordAriaLabel: string;
    hidePasswordAriaLabel: string;
    createButton: string;
    creatingButton: string;
    emptyMessageError: string;
    messageTooLongError: string;
    passwordTooShortError: string;
    passwordStrengthWeak: string;
    passwordStrengthMedium: string;
    passwordStrengthStrong: string;
    rateLimitedError: string;
    serverError: string;
    encryptionError: string;
    oneTimeWarning: string;
    newSecretAriaLabel: string;
    e2eBadge: string;
    read: {
      prepBadge: string;
      prepTitle: string;
      prepDescription: string;
      passwordRequiredDescription: string;
      passwordInputLabel: string;
      passwordInputPlaceholder: string;
      passwordRequiredError: string;
      revealButton: string;
      revealingButton: string;
      revealedBadge: string;
      revealedTitle: string;
      revealedWarning: string;
      copyMessageButton: string;
      copiedMessageButton: string;
      createNewSecretButton: string;
      missingKeyBadge: string;
      missingKeyTitle: string;
      missingKeyDescription: string;
      consumedBadge: string;
      consumedTitle: string;
      consumedDescription: string;
      expiredBadge: string;
      expiredTitle: string;
      expiredDescription: string;
      wrongPasswordError: string;
      wrongPasswordConsumedNotice: string;
      networkConsumeErrorTitle: string;
      networkConsumeErrorDescription: string;
    };
  };
  form: {
    destinationLabel: string;
    destinationPlaceholder: string;
    clearInputAriaLabel: string;
    generateButton: string;
    generatingButton: string;
    advancedOptions: string;
    modifiedBadge: string;
    resetOptions: string;
    customSlugLabel: string;
    customSlugPlaceholder: string;
    maxViewsLabel: string;
    decreaseViewsAria: string;
    increaseViewsAria: string;
    customExpirationLabel: string;
    expiredMessageLabel: string;
    expiredMessagePlaceholder: string;
    expirationPresets: Record<ExpirationPreset, string>;
    urlErrors: Record<UrlValidationErrorCode, string>;
    slugErrors: Record<SlugValidationErrorCode, string>;
    apiErrors: Record<CreateLinkErrorCode, string>;
  };
  result: {
    readyStatus: string;
    expiredStatus: string;
    copyButton: string;
    copiedButton: string;
    qrButton: string;
    qrAriaLabel: string;
    openLinkAriaLabel: string;
    newLinkAriaLabel: string;
    newLinkButton: string;
    burnedTitle: string;
    defaultExpiredMessage: string;
    singleRemainingView: string;
    multipleRemainingViews: (count: number) => string;
  };
  expiredPage: {
    badge: string;
    title: string;
    defaultMessage: string;
    createNewButton: string;
  };
  notFoundPage: {
    badge: string;
    title: string;
    description: string;
    backHomeButton: string;
  };
  about: {
    title: string;
    introParagraph1: string;
    introParagraph2: string;
    linksTitle: string;
    linksParagraph1: string;
    linksParagraph2: string;
    linksParagraph3: string;
    secretsTitle: string;
    secretsParagraph1: string;
    secretsParagraph2: string;
    secretsParagraph3: string;
    secretsParagraph4: string;
  };
  files: {
    title: string;
    subtitle: string;
    tabSend: string;
    tabRequest: string;
    send: {
      dragDropNotice: string;
      maxSizeNotice: string;
      expiration: string;
      maxDownloads: string;
      passwordLabel: string;
      passwordPlaceholder: string;
      uploading: string;
      generateButton: string;
      linkCreated: string;
      linkWarning: string;
      copyLink: string;
      copied: string;
    };
    request: {
      titleLabel: string;
      titlePlaceholder: string;
      maxFilesLabel: string;
      maxFileSizeLabel: string;
      expirationLabel: string;
      generateButton: string;
      creatingButton: string;
      requestCreated: string;
      publicLinkLabel: string;
      ownerLinkLabel: string;
      ownerWarning: string;
      copyLink: string;
      copied: string;
    };
    download: {
      title: string;
      subtitle: string;
      downloadButton: string;
      downloading: string;
      passwordRequired: string;
      passwordPlaceholder: string;
      passwordSubmit: string;
      wrongPassword: string;
      expiredTitle: string;
      expiredDescription: string;
      downloadSuccess: string;
    };
    guest: {
      title: string;
      subtitle: string;
      fingerprintVerified: string;
      fingerprintMismatch: string;
      uploadButton: string;
      uploading: string;
      uploadSuccess: string;
      closedOrExpired: string;
    };
    manage: {
      title: string;
      receivedFiles: string;
      noFiles: string;
      downloadFile: string;
      deleteFile: string;
      closeRequest: string;
      closing: string;
      requestClosed: string;
    };
  };
}

export const translations: Record<Locale, Dictionary> = {
  en: {
    meta: {
      homeAriaLabel: "ONCE Home",
      headerNavAriaLabel: "Main navigation",
      footerNavAriaLabel: "Footer navigation",
      links: "Link",
      secrets: "Secrets",
      files: "Files",
      about: "ONCE",
      github: "GitHub",
      switchThemeToLight: "Switch to light mode",
      switchThemeToDark: "Switch to dark mode",
      languageSelectorAriaLabel: "Select language",
    },
    hero: {
      title: "Temporary links.",
      subtitle:
        "Create and share links with limited access and automatic expiration.",
    },
    secrets: {
      title: "Secrets.",
      subtitle:
        "Share private messages that can be read only once and then become inaccessible.",
      messageLabel: "Secret message",
      messagePlaceholder: "Write the private message to share...",
      clearMessageAriaLabel: "Clear message",
      expirationLabel: "Expiration",
      passwordLabel: "Password protection",
      passwordOptionalBadge: "Optional",
      passwordActiveBadge: "Protected",
      passwordPlaceholder: "Enter a password to protect the message...",
      passwordSecurityHint:
        "Derived client-side via PBKDF2 + HKDF. Use a strong password to resist offline dictionary attacks if the link is intercepted.",
      showPasswordAriaLabel: "Show password",
      hidePasswordAriaLabel: "Hide password",
      createButton: "Create Secret",
      creatingButton: "Encrypting...",
      emptyMessageError: "Please enter a message to share.",
      messageTooLongError: "Message cannot exceed 4000 characters.",
      passwordTooShortError: "Password must be at least 8 characters.",
      passwordStrengthWeak: "Too short (min. 8 chars)",
      passwordStrengthMedium: "Good",
      passwordStrengthStrong: "Strong",
      rateLimitedError:
        "Too many secrets created recently. Please wait a moment and try again.",
      serverError:
        "Unable to save the encrypted secret right now. Please try again.",
      encryptionError:
        "Failed to encrypt the message in your browser. Ensure Web Crypto is available.",
      oneTimeWarning:
        "This message can only be read once and will no longer be recoverable.",
      newSecretAriaLabel: "Create another secret",
      e2eBadge: "AES-256-GCM",
      read: {
        prepBadge: "Encrypted Secret",
        prepTitle: "You have received a one-time encrypted message.",
        prepDescription:
          "Revealing this message will permanently destroy it from the server.",
        passwordRequiredDescription:
          "This secret is protected with a password. Enter it below before revealing the message.",
        passwordInputLabel: "Decryption password",
        passwordInputPlaceholder: "Enter password...",
        passwordRequiredError: "Please enter the password to decrypt this secret.",
        revealButton: "Show secret",
        revealingButton: "Decrypting...",
        revealedBadge: "Burned on server",
        revealedTitle: "Secret message",
        revealedWarning:
          "This secret has been permanently destroyed on the server.",
        copyMessageButton: "Copy message",
        copiedMessageButton: "Copied",
        createNewSecretButton: "Create a new secret",
        missingKeyBadge: "Incomplete Link",
        missingKeyTitle: "Decryption key missing.",
        missingKeyDescription:
          "The link is missing the decryption key after the # symbol. If you refreshed the page, the key was removed to protect your privacy: please reopen the original link from your chat or email.",
        consumedBadge: "Destroyed",
        consumedTitle: "This secret is no longer available.",
        consumedDescription:
          "This secret has already been read and permanently destroyed, or does not exist.",
        expiredBadge: "Expired",
        expiredTitle: "This secret has expired.",
        expiredDescription:
          "This secret reached its expiration time before being read and is no longer accessible.",
        wrongPasswordError:
          "Decryption failed: the password is incorrect or the link key was altered.",
        wrongPasswordConsumedNotice:
          "The ciphertext has already been consumed and erased from the server. You can retry the password before closing this tab, but reloading will permanently lose the message.",
        networkConsumeErrorTitle: "Network error during consumption.",
        networkConsumeErrorDescription:
          "The connection dropped while requesting the secret. If the request reached the server, the secret was irreversibly destroyed and cannot be recovered.",
      },
    },
    form: {
      destinationLabel: "Destination URL",
      destinationPlaceholder: "Paste your destination URL...",
      clearInputAriaLabel: "Clear URL input",
      generateButton: "Generate Link",
      generatingButton: "Generating...",
      advancedOptions: "Advanced options",
      modifiedBadge: "Modified",
      resetOptions: "Reset",
      customSlugLabel: "Custom slug",
      customSlugPlaceholder: "custom-alias",
      maxViewsLabel: "Maximum views",
      decreaseViewsAria: "Decrease maximum views",
      increaseViewsAria: "Increase maximum views",
      customExpirationLabel: "Custom expiration",
      expiredMessageLabel: "Custom expired message",
      expiredMessagePlaceholder:
        "This link has already been viewed and no longer exists.",
      expirationPresets: {
        never: "No limit",
        "15m": "15m",
        "1h": "1h",
        "24h": "24h",
        "7d": "7d",
      },
      urlErrors: {
        empty: "Please enter a destination URL.",
        url_too_long: "Destination URL cannot exceed 2048 characters.",
        spaces: "URL cannot contain spaces or control characters.",
        protocol: "URL must use HTTP or HTTPS protocol.",
        domain: "Please enter a valid domain name (e.g., example.com).",
        self_redirect: "Destination URL cannot point to ONCE itself.",
        invalid_url: "Please enter a valid URL.",
      },
      slugErrors: {
        slug_short: "Custom slug must be at least 3 characters.",
        slug_long: "Custom slug cannot exceed 32 characters.",
        slug_invalid:
          "Only letters, numbers, hyphens, and underscores are allowed.",
        slug_reserved: "This slug is reserved and cannot be used.",
        slug_taken: "This custom slug is already in use.",
      },
      apiErrors: {
        empty: "Please enter a destination URL.",
        url_too_long: "Destination URL cannot exceed 2048 characters.",
        spaces: "URL cannot contain spaces or control characters.",
        protocol: "URL must use HTTP or HTTPS protocol.",
        domain: "Please enter a valid domain name (e.g., example.com).",
        self_redirect: "Destination URL cannot point to ONCE itself.",
        invalid_url: "Please enter a valid URL.",
        slug_short: "Custom slug must be at least 3 characters.",
        slug_long: "Custom slug cannot exceed 32 characters.",
        slug_invalid:
          "Only letters, numbers, hyphens, and underscores are allowed.",
        slug_reserved: "This slug is reserved and cannot be used.",
        slug_taken: "This custom slug is already in use.",
        invalid_max_views: "Maximum views must be between 1 and 1000.",
        invalid_expiration: "Invalid expiration option selected.",
        message_too_long:
          "Custom expired message cannot exceed 140 characters.",
        rate_limited:
          "Too many links generated recently. Please wait a moment and try again.",
        server_error:
          "Unable to generate link right now. Please check server configuration and try again.",
      },
    },
    result: {
      readyStatus: "Active",
      expiredStatus: "Expired",
      copyButton: "Copy",
      copiedButton: "Copied",
      qrButton: "QR",
      qrAriaLabel: "Toggle QR code",
      openLinkAriaLabel: "Open short link in new tab",
      newLinkAriaLabel: "Create another link",
      newLinkButton: "New",
      burnedTitle: "Link expired",
      defaultExpiredMessage:
        "This link has reached its maximum visits and no longer exists.",
      singleRemainingView: "1 view left",
      multipleRemainingViews: (count: number) => `${count} views left`,
    },
    expiredPage: {
      badge: "Expired",
      title: "This link has expired.",
      defaultMessage:
        "This link has already been opened or has expired, and no longer exists.",
      createNewButton: "Create a new link",
    },
    notFoundPage: {
      badge: "404",
      title: "Link not found.",
      description:
        "The link you followed does not exist or may have been mistyped.",
      backHomeButton: "Back to ONCE",
    },
    about: {
      title: "ONCE",
      introParagraph1:
        "ONCE is an open source platform dedicated to temporary sharing of links and private information.",
      introParagraph2:
        "It comes from a simple idea: not everything we share needs to remain accessible forever. For this reason, ONCE offers tools that allow setting precise limits on content availability, without requiring accounts, registrations, or complex configurations.",
      linksTitle: "LINK",
      linksParagraph1:
        "LINK allows you to create temporary URLs that automatically redirect to a destination chosen by the user.",
      linksParagraph2:
        "Each link is identified by a unique slug and can be configured by defining a maximum number of visits and a time expiration. When a recipient opens the link, the system verifies that it is still valid and, if so, immediately redirects them to the original destination. Once the visit limit is reached or the expiration has passed, the link becomes unusable.",
      linksParagraph3:
        "Access management takes place through PostgreSQL and atomic functions that prevent simultaneous requests from exceeding the allowed number of uses. In this way, even in the presence of multiple concurrent openings, the configured limit is respected.",
      secretsTitle: "SECRETS",
      secretsParagraph1:
        "SECRETS is the tool dedicated to sharing private messages through an end-to-end encryption system.",
      secretsParagraph2:
        "The message is encrypted directly in the browser before being sent to the server, using AES-256-GCM. When a password is set, key derivation combines PBKDF2 and HKDF. The database stores exclusively the encrypted content and the metadata required for its management.",
      secretsParagraph3:
        "The recipient can request to view the message only once. The server verifies the availability of the secret and atomically records its consumption before returning the encrypted content, which is decrypted locally in the browser. It is also possible to add password protection and a time expiration.",
      secretsParagraph4:
        "The goal is to ensure that the server can manage and distribute messages without having access to their original content.",
    },
    files: {
      title: "Files.",
      subtitle:
        "End-to-end encrypted file sharing and zero-knowledge file requests.",
      tabSend: "Send",
      tabRequest: "Request",
      send: {
        dragDropNotice: "Drag and drop a file, or click to browse",
        maxSizeNotice: "Up to 45 MB • AES-256-GCM chunked encryption",
        expiration: "Expiration",
        maxDownloads: "Download authorizations",
        passwordLabel: "Password protection",
        passwordPlaceholder: "Enter optional password...",
        uploading: "Encrypting & uploading...",
        generateButton: "Send File",
        linkCreated: "File link ready",
        linkWarning:
          "Save this link now. It contains the decryption key in the fragment and is never stored on the server.",
        copyLink: "Copy Link",
        copied: "Copied",
      },
      request: {
        titleLabel: "Request title",
        titlePlaceholder: "e.g. Identity documents, contract...",
        maxFilesLabel: "Max files",
        maxFileSizeLabel: "Max file size",
        expirationLabel: "Expiration",
        generateButton: "Create Request",
        creatingButton: "Creating request...",
        requestCreated: "File request ready",
        publicLinkLabel: "Public upload link (share with guest)",
        ownerLinkLabel: "Private management link (keep secret)",
        ownerWarning:
          "Keep your management link safe. It contains your private ECDH key to decrypt uploaded files.",
        copyLink: "Copy Link",
        copied: "Copied",
      },
      download: {
        title: "Download file",
        subtitle: "This file is protected with end-to-end client-side encryption.",
        downloadButton: "Download & Decrypt",
        downloading: "Decrypting file...",
        passwordRequired: "This file is password-protected. Enter the password below.",
        passwordPlaceholder: "Enter password...",
        passwordSubmit: "Verify & Download",
        wrongPassword: "Decryption failed: incorrect password.",
        expiredTitle: "File unavailable",
        expiredDescription: "This transfer has expired or reached its maximum download limit.",
        downloadSuccess: "File downloaded and decrypted successfully.",
      },
      guest: {
        title: "Upload file",
        subtitle: "The file will be encrypted in your browser before upload.",
        fingerprintVerified: "Creator key authenticated via URL fingerprint",
        fingerprintMismatch: "CRITICAL: Public key fingerprint mismatch! Do not upload.",
        uploadButton: "Encrypt & Upload File",
        uploading: "Encrypting and uploading file...",
        uploadSuccess: "File encrypted and uploaded successfully.",
        closedOrExpired: "This file request is closed or has expired.",
      },
      manage: {
        title: "Manage File Request",
        receivedFiles: "Received files",
        noFiles: "No files received yet.",
        downloadFile: "Download",
        deleteFile: "Delete",
        closeRequest: "Close Request",
        closing: "Closing...",
        requestClosed: "This request has been permanently closed.",
      },
    },
  },
  it: {
    meta: {
      homeAriaLabel: "Home di ONCE",
      headerNavAriaLabel: "Navigazione principale",
      footerNavAriaLabel: "Navigazione piè di pagina",
      links: "Link",
      secrets: "Segreti",
      files: "Files",
      about: "ONCE",
      github: "GitHub",
      switchThemeToLight: "Passa al tema chiaro",
      switchThemeToDark: "Passa al tema scuro",
      languageSelectorAriaLabel: "Seleziona lingua",
    },
    hero: {
      title: "Link temporanei.",
      subtitle:
        "Crea e condividi link con accessi limitati e scadenza automatica.",
    },
    secrets: {
      title: "Segreti.",
      subtitle:
        "Condividi messaggi privati che possono essere letti una sola volta e poi diventano inaccessibili.",
      messageLabel: "Messaggio segreto",
      messagePlaceholder: "Scrivi il messaggio privato da condividere...",
      clearMessageAriaLabel: "Cancella messaggio",
      expirationLabel: "Scadenza",
      passwordLabel: "Proteggi con password",
      passwordOptionalBadge: "Opzionale",
      passwordActiveBadge: "Protetto",
      passwordPlaceholder:
        "Inserisci una password per proteggere il messaggio...",
      passwordSecurityHint:
        "Derivata lato client con PBKDF2 + HKDF. Usa una password robusta per resistere ad attacchi a dizionario offline se il link viene intercettato.",
      showPasswordAriaLabel: "Mostra password",
      hidePasswordAriaLabel: "Nascondi password",
      createButton: "Crea segreto",
      creatingButton: "Cifratura...",
      emptyMessageError: "Inserisci un messaggio da condividere.",
      messageTooLongError: "Il messaggio non può superare i 4000 caratteri.",
      passwordTooShortError: "La password deve contenere almeno 8 caratteri.",
      passwordStrengthWeak: "Troppo corta (min. 8 caratteri)",
      passwordStrengthMedium: "Robusta",
      passwordStrengthStrong: "Molto robusta",
      rateLimitedError:
        "Troppi segreti creati di recente. Attendi qualche istante e riprova.",
      serverError:
        "Impossibile salvare il segreto cifrato al momento. Riprova.",
      encryptionError:
        "Impossibile cifrare il messaggio nel browser. Verifica che Web Crypto sia disponibile.",
      oneTimeWarning:
        "Questo messaggio può essere letto una sola volta e non sarà più recuperabile.",
      newSecretAriaLabel: "Crea un altro segreto",
      e2eBadge: "AES-256-GCM",
      read: {
        prepBadge: "Segreto cifrato",
        prepTitle: "Hai ricevuto un messaggio cifrato monouso.",
        prepDescription:
          "Rivelando questo messaggio lo distruggerai definitivamente dal server.",
        passwordRequiredDescription:
          "Questo segreto è protetto da password. Inseriscila qui sotto prima di rivelare il messaggio.",
        passwordInputLabel: "Password di decifratura",
        passwordInputPlaceholder: "Inserisci la password...",
        passwordRequiredError:
          "Inserisci la password per decifrare questo segreto.",
        revealButton: "Mostra segreto",
        revealingButton: "Decifratura...",
        revealedBadge: "Distrutto sul server",
        revealedTitle: "Messaggio segreto",
        revealedWarning:
          "Questo segreto è stato distrutto definitivamente sul server.",
        copyMessageButton: "Copia messaggio",
        copiedMessageButton: "Copiato",
        createNewSecretButton: "Crea un nuovo segreto",
        missingKeyBadge: "Link incompleto",
        missingKeyTitle: "Chiave di decifratura mancante.",
        missingKeyDescription:
          "Il link non contiene la chiave crittografica dopo il simbolo #. Se hai ricaricato la pagina, la chiave è stata rimossa per proteggere la tua privacy: riapri il link originale ricevuto nella chat o email.",
        consumedBadge: "Distrutto",
        consumedTitle: "Questo segreto non è più disponibile.",
        consumedDescription:
          "Questo segreto è già stato letto e distrutto definitivamente, oppure non esiste.",
        expiredBadge: "Scaduto",
        expiredTitle: "Questo segreto è scaduto.",
        expiredDescription:
          "Questo segreto ha superato il limite di tempo prima di essere letto e non è più accessibile.",
        wrongPasswordError:
          "Decifratura fallita: la password è errata o la chiave nel link è stata alterata.",
        wrongPasswordConsumedNotice:
          "Il testo cifrato è già stato consumato ed eliminato dal server. Puoi riprovare la password prima di chiudere questa scheda, ma ricaricando la pagina il messaggio andrà perso definitivamente.",
        networkConsumeErrorTitle: "Errore di rete durante il consumo.",
        networkConsumeErrorDescription:
          "La connessione si è interrotta durante la richiesta del segreto. Se la richiesta ha raggiunto il server, il segreto è stato distrutto irreversibilmente e non può essere recuperato.",
      },
    },
    form: {
      destinationLabel: "URL di destinazione",
      destinationPlaceholder: "Incolla l'URL di destinazione...",
      clearInputAriaLabel: "Cancella URL inserito",
      generateButton: "Genera Link",
      generatingButton: "Generazione...",
      advancedOptions: "Opzioni avanzate",
      modifiedBadge: "Modificato",
      resetOptions: "Ripristina",
      customSlugLabel: "Slug personalizzato",
      customSlugPlaceholder: "alias-personalizzato",
      maxViewsLabel: "Visite massime",
      decreaseViewsAria: "Riduci visite massime",
      increaseViewsAria: "Aumenta visite massime",
      customExpirationLabel: "Scadenza",
      expiredMessageLabel: "Messaggio di link scaduto",
      expiredMessagePlaceholder:
        "Questo link è già stato visualizzato e non esiste più.",
      expirationPresets: {
        never: "Illimitata",
        "15m": "15m",
        "1h": "1h",
        "24h": "24h",
        "7d": "7g",
      },
      urlErrors: {
        empty: "Inserisci un URL di destinazione.",
        url_too_long: "L'URL di destinazione non può superare i 2048 caratteri.",
        spaces: "L'URL non può contenere spazi o caratteri di controllo.",
        protocol: "L'URL deve utilizzare il protocollo HTTP o HTTPS.",
        domain: "Inserisci un dominio valido (es. example.com).",
        self_redirect: "L'URL di destinazione non può puntare a ONCE stesso.",
        invalid_url: "Inserisci un URL valido.",
      },
      slugErrors: {
        slug_short: "Lo slug deve contenere almeno 3 caratteri.",
        slug_long: "Lo slug non può superare i 32 caratteri.",
        slug_invalid:
          "Sono consentiti solo lettere, numeri, trattini e underscore.",
        slug_reserved: "Questo slug è riservato e non può essere utilizzato.",
        slug_taken: "Questo slug personalizzato è già in uso.",
      },
      apiErrors: {
        empty: "Inserisci un URL di destinazione.",
        url_too_long: "L'URL di destinazione non può superare i 2048 caratteri.",
        spaces: "L'URL non può contenere spazi o caratteri di controllo.",
        protocol: "L'URL deve utilizzare il protocollo HTTP o HTTPS.",
        domain: "Inserisci un dominio valido (es. example.com).",
        self_redirect: "L'URL di destinazione non può puntare a ONCE stesso.",
        invalid_url: "Inserisci un URL valido.",
        slug_short: "Lo slug deve contenere almeno 3 caratteri.",
        slug_long: "Lo slug non può superare i 32 caratteri.",
        slug_invalid:
          "Sono consentiti solo lettere, numeri, trattini e underscore.",
        slug_reserved: "Questo slug è riservato e non può essere utilizzato.",
        slug_taken: "Questo slug personalizzato è già in uso.",
        invalid_max_views:
          "Il numero massimo di visite deve essere compreso tra 1 e 1000.",
        invalid_expiration: "Opzione di scadenza non valida.",
        message_too_long:
          "Il messaggio personalizzato non può superare i 140 caratteri.",
        rate_limited:
          "Troppi link generati di recente. Attendi qualche istante e riprova.",
        server_error:
          "Impossibile generare il link al momento. Verifica la configurazione del server e riprova.",
      },
    },
    result: {
      readyStatus: "Attivo",
      expiredStatus: "Scaduto",
      copyButton: "Copia",
      copiedButton: "Copiato",
      qrButton: "QR",
      qrAriaLabel: "Mostra o nascondi codice QR",
      openLinkAriaLabel: "Apri link breve in una nuova scheda",
      newLinkAriaLabel: "Crea un altro link",
      newLinkButton: "Nuovo",
      burnedTitle: "Link scaduto",
      defaultExpiredMessage:
        "Questo link ha raggiunto il numero massimo di visite e non esiste più.",
      singleRemainingView: "1 visita rimanente",
      multipleRemainingViews: (count: number) => `${count} visite rimanenti`,
    },
    expiredPage: {
      badge: "Scaduto",
      title: "Questo link è scaduto.",
      defaultMessage:
        "Questo link è già stato aperto o è scaduto, e non esiste più.",
      createNewButton: "Crea un nuovo link",
    },
    notFoundPage: {
      badge: "404",
      title: "Link non trovato.",
      description:
        "Il link che hai seguito non esiste o potrebbe essere stato digitato in modo errato.",
      backHomeButton: "Torna su ONCE",
    },
    about: {
      title: "ONCE",
      introParagraph1:
        "ONCE è una piattaforma open source dedicata alla condivisione temporanea di link e informazioni private.",
      introParagraph2:
        "Nasce da un’idea semplice: non tutto ciò che condividiamo deve rimanere accessibile per sempre. Per questo ONCE offre strumenti che permettono di stabilire limiti precisi alla disponibilità dei contenuti, senza richiedere account, registrazioni o configurazioni complesse.",
      linksTitle: "LINK",
      linksParagraph1:
        "LINK permette di creare URL temporanei che reindirizzano automaticamente verso una destinazione scelta dall’utente.",
      linksParagraph2:
        "Ogni link è identificato da uno slug univoco e può essere configurato definendo un numero massimo di accessi e una scadenza temporale. Quando un destinatario apre il link, il sistema verifica che sia ancora valido e, in caso positivo, lo reindirizza immediatamente alla destinazione originale. Una volta raggiunto il limite di accessi o superata la scadenza, il link diventa inutilizzabile.",
      linksParagraph3:
        "La gestione degli accessi avviene attraverso PostgreSQL e funzioni atomiche che impediscono a richieste simultanee di superare il numero di utilizzi consentiti. In questo modo, anche in presenza di più aperture contemporanee, il limite impostato viene rispettato.",
      secretsTitle: "SEGRETI",
      secretsParagraph1:
        "SEGRETI è lo strumento dedicato alla condivisione di messaggi privati attraverso un sistema di cifratura end-to-end.",
      secretsParagraph2:
        "Il messaggio viene cifrato direttamente nel browser prima di essere inviato al server, utilizzando AES-256-GCM. Quando viene impostata una password, la derivazione della chiave combina PBKDF2 e HKDF. Il database conserva esclusivamente il contenuto cifrato e i metadati necessari alla sua gestione.",
      secretsParagraph3:
        "Il destinatario può richiedere la visualizzazione del messaggio una sola volta. Il server verifica la disponibilità del segreto e ne registra atomicamente il consumo prima di restituire il contenuto cifrato, che viene decifrato localmente nel browser. È inoltre prevista la possibilità di aggiungere una protezione tramite password e una scadenza temporale.",
      secretsParagraph4:
        "L’obiettivo è fare in modo che il server possa gestire e distribuire i messaggi senza avere accesso al loro contenuto originale.",
    },
    files: {
      title: "File.",
      subtitle:
        "Condivisione di file con cifratura end-to-end e richieste file zero-knowledge.",
      tabSend: "Invia",
      tabRequest: "Richiedi",
      send: {
        dragDropNotice: "Trascina qui il file, oppure clicca per selezionarlo",
        maxSizeNotice: "Fino a 45 MB • Cifratura a chunk AES-256-GCM",
        expiration: "Scadenza",
        maxDownloads: "Autorizzazioni di download",
        passwordLabel: "Proteggi con password",
        passwordPlaceholder: "Inserisci password opzionale...",
        uploading: "Cifratura e caricamento...",
        generateButton: "Invia File",
        linkCreated: "Link del file pronto",
        linkWarning:
          "Conserva questo link adesso. Contiene la chiave di decifratura nel frammento e non è salvato sul server.",
        copyLink: "Copia Link",
        copied: "Copiato",
      },
      request: {
        titleLabel: "Titolo della richiesta",
        titlePlaceholder: "es. Documenti d'identità, contratto...",
        maxFilesLabel: "Numero massimo di file",
        maxFileSizeLabel: "Dimensione massima per file",
        expirationLabel: "Scadenza",
        generateButton: "Crea Richiesta",
        creatingButton: "Creazione in corso...",
        requestCreated: "Richiesta file creata",
        publicLinkLabel: "Link pubblico (condividi con chi deve caricare)",
        ownerLinkLabel: "Link privato di gestione (conserva con cura)",
        ownerWarning:
          "Conserva il link di gestione al sicuro. Contiene la tua chiave privata ECDH necessaria per decifrare i file ricevuti.",
        copyLink: "Copia Link",
        copied: "Copiato",
      },
      download: {
        title: "Scarica file",
        subtitle: "Questo file è protetto da cifratura end-to-end client-side.",
        downloadButton: "Scarica e Decifra",
        downloading: "Decifratura in corso...",
        passwordRequired: "Questo file è protetto da password. Inseriscila per procedere.",
        passwordPlaceholder: "Inserisci password...",
        passwordSubmit: "Verifica e Scarica",
        wrongPassword: "Decifratura fallita: password errata.",
        expiredTitle: "File non disponibile",
        expiredDescription: "Questo trasferimento è scaduto o ha raggiunto il limite massimo di download.",
        downloadSuccess: "File scaricato e decifrato con successo.",
      },
      guest: {
        title: "Carica file",
        subtitle: "Il file verrà cifrato direttamente nel tuo browser prima dell'invio.",
        fingerprintVerified: "Chiave del destinatario autenticata tramite fingerprint",
        fingerprintMismatch: "ATTENZIONE: Il fingerprint della chiave pubblica non corrisponde! Non caricare file.",
        uploadButton: "Cifra e Carica File",
        uploading: "Cifratura e caricamento in corso...",
        uploadSuccess: "File cifrato e inviato con successo.",
        closedOrExpired: "Questa richiesta di file è chiusa o scaduta.",
      },
      manage: {
        title: "Gestione Richiesta File",
        receivedFiles: "File ricevuti",
        noFiles: "Nessun file ancora ricevuto.",
        downloadFile: "Scarica",
        deleteFile: "Elimina",
        closeRequest: "Chiudi Richiesta",
        closing: "Chiusura in corso...",
        requestClosed: "Questa richiesta è stata definitivamente chiusa.",
      },
    },
  },
};
