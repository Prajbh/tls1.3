(herald "TLS 1.3 Protocol Analyser"
	(algebra diffie-hellman))

;;working of the protocol using psk              
(defmacro (finkey psk)
  (hash psk "finished"))

(defmacro (serverfinished psk index n1 n2)
  (hash (finkey psk) (hash "Client-Hello" n1 index "Server-Hello" n2)))

(defmacro (clientfinished psk index n1 n2)
  (hash (finkey psk) (hash "Client-hello" n1 index "Server-Hello" n2 (serverfinished psk index n1 n2))))

(defprotocol tls diffie-hellman
  (defrole initialize
    (vars (psk skey)(index text))
    (trace
     (init (cat psk index)))
    (uniq-gen psk index))

 ;; client side                                  
 (defrole client
   (vars (a b name)(m d text)(n1 n2 data)(psk skey)(n index text))
   (trace
    (obsv (cat psk index))
    (send (cat "Client-hello" n1 index))
    (recv (cat "Server-hello" n2 (serverfinished psk index n1 n2)))
    (send (clientfinished psk index n1 n2))
    (send (enc n psk)))
    )

    
 ;;server side                                   
 (defrole server
  (vars (a b name)(m d text)(n1 n2 data)(psk skey)(index n text))
   (trace
    (recv (cat "Client-hello" n1 index))
    (obsv (cat psk index))
    (send (cat "Server-hello" n2 (serverfinished psk index n1 n2)))
    (recv (clientfinished psk index n1 n2))
    (recv (enc n psk)))
   ))

;;skeleton for client point of view              
(defskeleton tls
  (vars (a b name)(psk skey)(n1 n2 data)(index text))
  (defstrand client 5 (psk psk)(index index)(n1 n1)(n2 n2)) 
  (non-orig psk)
  (uniq-orig n1)
  )
                           
(defskeleton tls
  (vars (a b name)(psk skey)(n1 n2 data)(index text))
  (defstrand server 5 (psk psk)(index index)(n2 n2))
  (non-orig psk)
  (uniq-orig n2)
)

