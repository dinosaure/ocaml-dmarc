let domain_name = Alcotest.testable Domain_name.pp Domain_name.equal

let test00 =
  Alcotest.test_case "a.b.c.d.example.org" `Quick @@ fun () ->
  let domain = Domain_name.of_string_exn "a.b.c.d.example.org" in
  match Dmarc.organization_domain ~domain with
  | Some v ->
      Alcotest.(check domain_name)
        "example.org" v
        (Domain_name.of_string_exn "example.org")
  | None ->
      Alcotest.failf "Organization domain for %a not found" Domain_name.pp
        domain

let test01 =
  Alcotest.test_case "a.b.c.example.co.uk" `Quick @@ fun () ->
  let domain = Domain_name.of_string_exn "a.b.c.example.co.uk" in
  match Dmarc.organization_domain ~domain with
  | Some v ->
      Alcotest.(check domain_name)
        "example.co.uk" v
        (Domain_name.of_string_exn "example.co.uk")
  | None ->
      Alcotest.failf "Organization domain for %a not found" Domain_name.pp
        domain

let test02 =
  Alcotest.test_case "example.co.uk" `Quick @@ fun () ->
  let domain = Domain_name.of_string_exn "example.co.uk" in
  match Dmarc.organization_domain ~domain with
  | Some v -> Alcotest.(check domain_name) "example.co.uk" v domain
  | None ->
      Alcotest.failf "Organization domain for %a not found" Domain_name.pp
        domain

let test03 =
  Alcotest.test_case "co.uk" `Quick @@ fun () ->
  let domain = Domain_name.of_string_exn "co.uk" in
  match Dmarc.organization_domain ~domain with
  | Some v ->
      Alcotest.(check domain_name) "co.uk" v (Domain_name.of_string_exn "co.uk")
  | None ->
      Alcotest.failf "Organization domain for %a not found" Domain_name.pp
        domain

let () =
  Alcotest.run "organization domain"
    [ ("simple", [ test00; test01; test02; test03 ]) ]
