package main

import (
	"encoding/json"
	"fmt"
	"github.com/kinyoubenkyokai/ykvp/lib/yubico"
	"log"
	"os"

	"github.com/kinyoubenkyokai/ykvp/lib/entity"
	"github.com/kinyoubenkyokai/ykvp/lib/holder"
	"github.com/kinyoubenkyokai/ykvp/lib/verifier"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "",
		Usage: "",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "c",
				Usage: "Verifiable Credential",
			},
			&cli.IntFlag{
				Name:  "p",
				Value: 123456,
				Usage: "PIN code",
			},
		},
		Action: func(cCtx *cli.Context) error {
			vc := cCtx.String("c")
			if vc == "" {
				log.Println("no verifiable credential specified")
				return nil
			}
			pin := cCtx.Int("p")
			if pin == 0 {
				pin = 123456
			}
			credentials, err := entity.UnmarshalCredential([]byte(vc))
			if err != nil {
				panic(err)
			}
			nonce, err := verifier.CreateVerifier().MakeNonce()
			if err != nil {
				return err
			}

			pub, err := yubico.GenerateAndImportKeyToYubikey()
			if err != nil {
				return err
			}
			holder, err := holder.CreateHolder(pub)
			if err != nil {
				return err
			}
			presentation, err := holder.SignPresentation(
				entity.Credential{CredentialToSign: *credentials},
				nonce,
				int32(pin),
			)

			nicePrint(presentation, "Presentation")

			log.Println(pin)
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func nicePrint(i interface{}, name string) {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")

	fmt.Printf("\n***** %s *****\n\n", name)
	e.Encode(i)
}
