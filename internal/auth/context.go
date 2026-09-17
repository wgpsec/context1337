package auth

import "context"

type principalKey struct{}

func WithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, principal)
}

func FromContext(ctx context.Context) Principal {
	if ctx == nil {
		return AdminPrincipal("anonymous")
	}
	principal, ok := ctx.Value(principalKey{}).(Principal)
	if !ok {
		return AdminPrincipal("anonymous")
	}
	return principal
}
