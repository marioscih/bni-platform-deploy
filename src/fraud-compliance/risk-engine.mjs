export class RuleRiskEngine {
  constructor({ now = () => new Date(), maxSinglePaymentMinor = 500_000, maxSingleTransferMinor = 2_500_000, paymentVelocityCount = 8, velocityWindowMs = 10 * 60_000 } = {}) { Object.assign(this, { now, maxSinglePaymentMinor, maxSingleTransferMinor, paymentVelocityCount, velocityWindowMs }); }
  evaluate(context, state = null) {
    const reasons = [];
    if (context.amountMinor <= 0) reasons.push("INVALID_AMOUNT");
    if (context.operation === "BNI_PAY" && context.amountMinor > this.maxSinglePaymentMinor) reasons.push("SINGLE_PAYMENT_LIMIT");
    if (context.operation === "TRANSFER" && context.amountMinor > this.maxSingleTransferMinor) reasons.push("SINGLE_TRANSFER_LIMIT");
    if (state && context.deviceReference && state.devices[context.deviceReference]?.attestationVerdict === "UNTRUSTED") reasons.push("DEVICE_INTEGRITY");
    if (state && context.operation === "BNI_PAY") {
      const cutoff = this.now().getTime() - this.velocityWindowMs;
      const recent = Object.values(state.bniPayments).filter((payment) => payment.customerReference === context.customerReference && payment.status === "APPROVED" && new Date(payment.approvedAt).getTime() >= cutoff).length;
      if (recent >= this.paymentVelocityCount) reasons.push("PAYMENT_VELOCITY");
    }
    return { decision: reasons.length ? "DENY" : "ALLOW", reasons, policyVersion: "BNI-RISK-1" };
  }
}
