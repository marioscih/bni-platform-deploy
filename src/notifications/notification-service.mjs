import { BankError, iso, opaqueId, requireOpaque } from "../shared/kernel.mjs";
import { addAudit } from "../shared/repository.mjs";

const DEEP_LINKS = new Set(["HOME", "MOVEMENTS", "TRANSFER_DETAIL", "DOCUMENT_DETAIL", "BNI_PAY_DETAIL", "CARD_DETAIL"]);

export class NotificationService {
  constructor({ repository, pushAdapter = null, now = () => new Date() } = {}) { this.repository = repository; this.pushAdapter = pushAdapter; this.now = now; }

  async setPreferences(ownerReference, preferences) {
    return this.repository.transaction((state) => {
      state.notificationPreferences[requireOpaque(ownerReference)] = {
        transactional: preferences.transactional !== false,
        security: true,
        marketing: preferences.marketing === true,
        updatedAt: iso(this.now()),
      };
      return state.notificationPreferences[ownerReference];
    });
  }

  async projectPending(limit = 100) {
    const pending = this.repository.read((state) => Object.values(state.outbox).filter((event) => event.status === "PENDING" && new Date(event.nextAttemptAt) <= this.now()).sort((a, b) => a.occurredAt.localeCompare(b.occurredAt)).slice(0, limit));
    const results = [];
    for (const event of pending) results.push(await this.#project(event));
    return results;
  }

  async #project(event) {
    const notification = await this.repository.transaction((state) => {
      const current = state.outbox[event.eventId];
      if (!current || current.status !== "PENDING") return null;
      const existing = Object.values(state.inbox).find((entry) => entry.sourceEventId === current.eventId);
      if (existing) { current.status = "DELIVERED"; current.deliveredAt = iso(this.now()); return existing; }
      const mapped = this.#map(current);
      const entry = { notificationReference: opaqueId("notification"), ownerReference: current.aggregateReference, sourceEventId: current.eventId, title: mapped.title, body: mapped.body, category: mapped.category, deepLink: mapped.deepLink, readAt: null, createdAt: iso(this.now()), delivery: "INBOX" };
      state.inbox[entry.notificationReference] = entry; current.status = "DELIVERED"; current.deliveredAt = iso(this.now()); current.attempts += 1;
      addAudit(state, { type: "NOTIFICATION_PROJECTED", subjectReference: entry.notificationReference, actorReference: entry.ownerReference, outcome: "INBOX", correlationId: current.correlationId }, this.now);
      return entry;
    });
    if (notification && this.pushAdapter?.configured === true) {
      try { await this.pushAdapter.send({ title: notification.title, body: notification.body, deepLink: notification.deepLink }); }
      catch { await this.repository.transaction((state) => { const item = state.inbox[notification.notificationReference]; item.delivery = "INBOX_PUSH_FAILED"; return item; }); }
    }
    return notification;
  }

  list(ownerReference) { return this.repository.read((state) => Object.values(state.inbox).filter((entry) => entry.ownerReference === ownerReference).sort((a, b) => b.createdAt.localeCompare(a.createdAt))); }

  async markRead(notificationReference, ownerReference) {
    return this.repository.transaction((state) => {
      const item = state.inbox[requireOpaque(notificationReference)]; if (!item || item.ownerReference !== ownerReference) throw new BankError("NOTIFICATION_NOT_FOUND", 404);
      item.readAt ??= iso(this.now()); return item;
    });
  }

  metrics() { return this.repository.read((state) => ({ pending: Object.values(state.outbox).filter((e) => e.status === "PENDING").length, delivered: Object.values(state.outbox).filter((e) => e.status === "DELIVERED").length, dead: Object.values(state.outbox).filter((e) => e.status === "DEAD").length })); }

  #map(event) {
    const mapping = {
      DEVICE_ENROLLED: ["Nuovo dispositivo", "Un nuovo dispositivo è stato associato al tuo profilo.", "SECURITY", "HOME"],
      DEVICE_STATUS_CHANGED: ["Stato dispositivo aggiornato", "La sicurezza del dispositivo è stata aggiornata.", "SECURITY", "HOME"],
      TRANSFER_SETTLED: ["Bonifico eseguito", "Il bonifico è stato contabilizzato.", "TRANSACTION", "TRANSFER_DETAIL"],
      DOCUMENT_AVAILABLE: ["Nuovo documento", "Una nuova ricevuta è disponibile.", "DOCUMENT", "DOCUMENT_DETAIL"],
      JOURNAL_BOOKED: ["Movimento contabilizzato", "È disponibile un nuovo movimento.", "TRANSACTION", "MOVEMENTS"],
      BNI_PAY_APPROVED: ["Pagamento BNI Pay", "Il pagamento è stato approvato.", "TRANSACTION", "BNI_PAY_DETAIL"],
    };
    const [title, body, category, deepLink] = mapping[event.type] ?? ["Aggiornamento BNI", "È disponibile un aggiornamento nel tuo profilo.", "SERVICE", "HOME"];
    if (!DEEP_LINKS.has(deepLink)) throw new BankError("UNSAFE_DEEP_LINK", 500);
    return { title, body, category, deepLink };
  }
}

export class UnavailablePushAdapter { constructor() { this.configured = false; } async send() { throw new BankError("PUSH_PROVIDER_NOT_CONFIGURED", 503, true); } }
