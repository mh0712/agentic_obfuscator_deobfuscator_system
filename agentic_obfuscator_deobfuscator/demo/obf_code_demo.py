class 𝒜:
    def __init__(𝓈, 𝓞, 𝓑=0):
        𝓈.𝓍 = 𝓞
        𝓈.𝓎 = 𝓑

    def 𝒹(𝓈, 𝓪):
        if 𝓪 > 0:
            𝓈.𝓎 += 𝓪
            print(f"{𝓈.𝓍} " + bytes([100, 101, 112, 111, 115, 105, 116, 101, 100]).decode() + f" ${𝓪}. " + f"{'New balance'}: ${𝓈.𝓎}")
        else:
            print("".join(chr(i) for i in [68, 101, 112, 111, 115, 105, 116, 32, 97, 109, 111, 117, 110, 116, 32, 109, 117, 115, 116, 32, 98, 101, 32, 103, 114, 101, 97, 116, 101, 114, 32, 116, 104, 97, 110, 32, 48, 46]))

    def 𝓌(𝓈, 𝓪):
        if 𝓪 > 0 and 𝓪 <= 𝓈.𝓎:
            𝓈.𝓎 -= 𝓪
            print(f"{𝓈.𝓍} withdrew ${𝓪}. " + f"{'New balance'}: ${𝓈.𝓎}")
        elif 𝓪 > 𝓈.𝓎:
            print("".join(map(chr, [73, 110, 115, 117, 102, 102, 105, 99, 105, 101, 110, 116, 32, 98, 97, 108, 97, 110, 99, 101, 32, 102, 111, 114, 32, 119, 105, 116, 104, 100, 114, 97, 119, 97, 108, 46])))
        else:
            print("Withdrawal amount must be greater than 0.")

    def 𝓉(𝓈, 𝓪, 𝓇):
        if 𝓪 > 0 and 𝓪 <= 𝓈.𝓎:
            𝓈.𝓌(𝓪)
            𝓇.𝒹(𝓪)
            print(f"{𝓈.𝓍} transferred ${𝓪} to {𝓇.𝓍}.")
        else:
            print("Transfer failed. Insufficient balance or invalid amount.")

    def 𝓈𝒹(𝓈):
        print(f"{𝓈.𝓍}'s Account: ${𝓈.𝓎}")


class 𝒯:
    def __init__(self): self.𝓉𝓍 = []

    def 𝓇(self, 𝓉𝓍𝓃): self.𝓉𝓍.append(𝓉𝓍𝓃)

    def 𝓈𝒽(self):
        if len(self.𝓉𝓍) == 0:
            print("".join(chr(i) for i in [78, 111, 32, 116, 114, 97, 110, 115, 97, 99, 116, 105, 111, 110, 115, 32, 114, 101, 99, 111, 114, 100, 101, 100, 46]))
        else:
            print("Transaction History:")
            [print(f"{𝒾 + 1}. {𝓉}") for 𝒾, 𝓉 in enumerate(self.𝓉𝓍)]


𝓐𝓁 = 𝒜("".join([chr(65), chr(108), chr(105), chr(99), chr(101)]), 1000)
𝓑𝓸 = 𝒜("".join(map(chr, [66, 111, 98])), 500)
𝓣𝓗 = 𝒯()

[(lambda f: f())(lambda: 𝓐𝓁.𝒹(200)),
 (lambda f: f())(lambda: 𝓐𝓁.𝓌(150)),
 (lambda f: f())(lambda: 𝓑𝓸.𝒹(300)),
 (lambda f: f())(lambda: 𝓐𝓁.𝓉(500, 𝓑𝓸))]

for 𝓁𝒐𝓰 in [
    "Alice deposited $200",
    "Alice withdrew $150",
    "Bob deposited $300",
    "Alice transferred $500 to Bob"
]:
    𝓣𝓗.𝓇(𝓁𝒐𝓰)

𝓐𝓁.𝓈𝒹()
𝓑𝓸.𝓈𝒹()
𝓣𝓗.𝓈𝒽()
