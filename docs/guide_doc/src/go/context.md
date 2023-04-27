# Context

## Description


"`Context` is a struct assembling configuration from an input Protobuf. It's a wrapper of `SandwichContext` function in Sandwich library."

Inputs:
- [`Configuration`](./configuration.md)

Output:
- `Context` struct


## Usage

```go

// createContext creates return server or client context, depend on api.Configuration settings
func createContext(config *api.Configuration) (*sandwich.Context, error) {
	ctx, err := sandwich.NewContext(config)
	if err != nil {
		t.Errorf("Failed to create the server context: %v", err)
		panic("failed")
	}

	return ctx, nil
}

```
