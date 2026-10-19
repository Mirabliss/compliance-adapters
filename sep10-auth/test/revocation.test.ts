import { InMemoryRevocationStore } from '../src/revocation';

const ADDRESS = 'GDNOTPRESENTINANYMOCKWATCHLISTAAAAAAAAAAAAAAAAAAAAAAAAAA';

describe('InMemoryRevocationStore', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('reports an address as not revoked before any revoke() call', () => {
    const store = new InMemoryRevocationStore();
    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('permanently revokes an address when no `until` is given', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS);
    expect(store.isRevoked(ADDRESS)).toBe(true);

    jest.setSystemTime(new Date('2099-01-01T00:00:00.000Z'));
    expect(store.isRevoked(ADDRESS)).toBe(true);
  });

  it('treats a revocation with a future `until` as revoked until that time passes', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS, new Date('2026-01-01T00:10:00.000Z'));

    expect(store.isRevoked(ADDRESS)).toBe(true);

    jest.setSystemTime(new Date('2026-01-01T00:09:59.999Z'));
    expect(store.isRevoked(ADDRESS)).toBe(true);
  });

  it('treats a revocation with a past `until` as not revoked and self-cleans the entry', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS, new Date('2025-12-31T23:59:59.000Z'));

    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('treats a revocation as expired the instant `until` is reached (<=, not <)', () => {
    const store = new InMemoryRevocationStore();
    const now = new Date('2026-01-01T00:00:00.000Z');
    store.revoke(ADDRESS, now);

    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('expires a temporary revocation once `until` passes on a later check', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS, new Date('2026-01-01T00:00:30.000Z'));
    expect(store.isRevoked(ADDRESS)).toBe(true);

    jest.setSystemTime(new Date('2026-01-01T00:01:00.000Z'));
    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('unrevoke() lifts a permanent revocation', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS);
    expect(store.isRevoked(ADDRESS)).toBe(true);

    store.unrevoke(ADDRESS);
    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('unrevoke() lifts a temporary revocation before it would have expired', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS, new Date('2099-01-01T00:00:00.000Z'));
    expect(store.isRevoked(ADDRESS)).toBe(true);

    store.unrevoke(ADDRESS);
    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('unrevoke() on an address that was never revoked is a no-op', () => {
    const store = new InMemoryRevocationStore();
    expect(() => store.unrevoke(ADDRESS)).not.toThrow();
    expect(store.isRevoked(ADDRESS)).toBe(false);
  });

  it('tracks multiple addresses independently', () => {
    const store = new InMemoryRevocationStore();
    const otherAddress = 'GOTHERADDRESSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    store.revoke(ADDRESS);
    expect(store.isRevoked(ADDRESS)).toBe(true);
    expect(store.isRevoked(otherAddress)).toBe(false);
  });

  it('list() returns currently revoked addresses, excluding expired ones', () => {
    const store = new InMemoryRevocationStore();
    store.revoke(ADDRESS);
    store.revoke('GTIMED', new Date('2026-01-01T00:00:10.000Z'));
    expect(store.list()).toEqual([ADDRESS, 'GTIMED']);

    jest.setSystemTime(new Date('2026-01-01T00:01:00.000Z'));
    expect(store.list()).toEqual([ADDRESS]);
  });

  describe('per-token revocation', () => {
    const JTI = 'abc123';
    const EXPIRES = new Date('2026-01-01T00:10:00.000Z');

    it('reports a token as not revoked before any revokeToken() call', () => {
      const store = new InMemoryRevocationStore();
      expect(store.isTokenRevoked(JTI)).toBe(false);
    });

    it('revokes a single token without revoking its address or other tokens', () => {
      const store = new InMemoryRevocationStore();
      store.revokeToken(JTI, EXPIRES);

      expect(store.isTokenRevoked(JTI)).toBe(true);
      expect(store.isTokenRevoked('other-jti')).toBe(false);
      expect(store.isRevoked(ADDRESS)).toBe(false);
    });

    it('works alongside per-address revocation', () => {
      const store = new InMemoryRevocationStore();
      store.revoke(ADDRESS);
      store.revokeToken(JTI, EXPIRES);

      expect(store.isRevoked(ADDRESS)).toBe(true);
      expect(store.isTokenRevoked(JTI)).toBe(true);
    });

    it('stops reporting the token as revoked once it expires', () => {
      const store = new InMemoryRevocationStore();
      store.revokeToken(JTI, EXPIRES);

      jest.setSystemTime(new Date('2026-01-01T00:09:59.999Z'));
      expect(store.isTokenRevoked(JTI)).toBe(true);

      jest.setSystemTime(new Date('2026-01-01T00:10:00.000Z'));
      expect(store.isTokenRevoked(JTI)).toBe(false);
    });

    it('prunes expired token revocations when another token is revoked', () => {
      const store = new InMemoryRevocationStore();
      store.revokeToken('short', new Date('2026-01-01T00:00:10.000Z'));
      store.revokeToken('long', EXPIRES);
      expect(store.tokenSize()).toBe(2);

      jest.setSystemTime(new Date('2026-01-01T00:01:00.000Z'));
      store.revokeToken('new', EXPIRES);
      expect(store.tokenSize()).toBe(2);
      expect(store.isTokenRevoked('short')).toBe(false);
    });

    it('ignores a token revocation whose expiry is already in the past', () => {
      const store = new InMemoryRevocationStore();
      store.revokeToken(JTI, new Date('2025-12-31T23:59:59.000Z'));
      expect(store.isTokenRevoked(JTI)).toBe(false);
      expect(store.tokenSize()).toBe(0);
    });
  });
});
