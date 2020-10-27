(herald "TLS 1.3"
;;	(algebra diffie-hellman)
	)

(defprotocol tls basic

  (defrole keyshare-initialize
    (vars (a b name) (index text) (psk skey))
    (trace
     (init (cat index a b psk))) ;; initialization of key for parties a and b
     ;;(init (cat index b a psk))) ;; added so CPSA knows the key is bidirectional
    (uniq-orig index)
    (non-orig psk))

  (defrole client
    (vars (a b name) (index n1 n2 text) (psk skey))
    (trace
     (obsv (cat index a b psk))
     (send (cat n1 index))
     (recv (cat n2 (hash (hash psk n1 n2) n1 index n2)))
     (send (hash (hash psk n1 n2) n1 index n2 (hash (hash psk n1 n2) n1 index n2)))
     )
    )

  (defrole server
    (vars (a b name) (index n1 n2 text) (psk skey))
    (trace
     (recv (cat n1 index))
     (obsv (cat index a b psk))
     (send (cat n2 (hash (hash psk n1 n2) n1 index n2)))
     (recv (hash (hash psk n1 n2) n1 index n2 (hash (hash psk n1 n2) n1 index n2)))
     )
    )
  (comment "Protocol without servername extension. Shows Selfie attack.")
  )

(defskeleton tls
  (vars (a b name) (n1 index text) (psk skey))
  (defstrand client 3 (a a) (b b) (n1 n1) (index index) (psk psk))
  (uniq-orig n1)
  )

(defskeleton tls
  (vars (a b name) (n2 index text) (psk skey))
  (defstrand server 4 (a a) (b b) (n2 n2) (index index) (psk psk))
  (uniq-orig n2)
  )

(defprotocol tls1 basic

  (defrole keyshare-initialize
    (vars (a b name) (index text) (psk skey))
    (trace
     (init (cat index a b psk))
     (init (cat index b a psk)))
    (uniq-orig index)
    (non-orig psk))

  (defrole client
    (vars (a b name) (index n1 n2 text) (psk skey))
    (trace
     (obsv (cat index a b psk))
     (send (cat n1 index)) ;; client hello
     (recv (cat n2 ;; server hello
		(enc b (hash psk n1 n2)) ;;encrypted extension servername
		(hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))))) ;; server finish
     (send (hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))
		 (hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))))) ;; clinet finish
     )
    )

  (defrole server
    (vars (a b name) (index n1 n2 text) (psk skey))
    (trace
     (recv (cat n1 index)) ;; client hello
     (obsv (cat index a b psk))
     (send (cat n2 ;; server hello
		(enc b (hash psk n1 n2)) ;; encrypted extension servername
		(hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))))) ;; server finish
     (recv (hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))
		 (hash (hash psk n1 n2) n1 index n2 (enc b (hash psk n1 n2))))) ;; client finish
     )
    )
  (comment "Protocol with servername extension. No selfie attack.")
  )

(defskeleton tls1
  (vars (a b name) (n1 index text) (psk skey))
  (defstrand client 3 (a a) (b b) (n1 n1) (index index) (psk psk))
  (uniq-orig n1)
  )

(defskeleton tls1
  (vars (a b name) (n2 index text) (psk skey))
  (defstrand server 4 (a a) (b b) (n2 n2) (index index) (psk psk))
  (uniq-orig n2)
  )

(defskeleton tls1 ;; Proof of no Selfie attack. Only works for keys talking to oneself.
  (vars (a b name) (n1 n2 index text) (psk skey))
  (defstrand client 4 (a a) (b b) (n1 n1) (n2 n2) (index index) (psk psk))
  (defstrand server 4 (a b) (b a) (n1 n1) (n2 n2) (index index) (psk psk))
  (uniq-orig n1 n2)
  )
