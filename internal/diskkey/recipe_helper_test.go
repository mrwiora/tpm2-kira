package diskkey

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseRecipe reads, for the tests, a recipe's number as String writes it ("0x1401").
func ParseRecipe(s string) (Recipe, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 16)
	if err != nil {
		return 0, fmt.Errorf("a recipe is a number like 0x1401, not %q", s)
	}
	r := Recipe(v)
	return r, r.Check()
}

// RecipeOfTokens is the recipe tried first, or 0.
func RecipeOfTokens(toks []LuksToken) Recipe {
	if rs := RecipesOfTokens(toks); len(rs) > 0 {
		return rs[0]
	}
	return 0
}
