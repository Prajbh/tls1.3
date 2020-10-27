(herald "TLS 1.3 Protocol Analyser"
	(algebra diffie-hellman))


;;macro to define for the finished key used in finished message
(defmacro (finkey psk)
  (hash psk "finished"))

;;macro to define the serverfinished message
(defmacro (serverfinished psk index n1 n2)
  (hash (finkey psk)
	(hash "Client-Hello" n1 index
	      "Server-Hello" n2 (enc b psk))))

;;macro to define the client finished message
(defmacro (clientfinished psk index n1 n2)
  (hash (finkey psk)
	(hash "Client-hello" n1 index
	      "Server-Hello" n2 (enc b psk) (serverfinished psk index n1 n2))))

;;working of the protocol using psk-only key exchange method
(defprotocol tls diffie-hellman
  ;; Keyshare-Initialse role that shares the externally establoished psk 
  (defrole initialize
    (vars (psk skey)(index text)) ;;variables and their type
    (trace
     (init (cat psk index))) ;;initialises psk and index
    (uniq-gen psk index)) ;;psk and index are uniquely generated here
  
 ;; client side                                  
 (defrole client
   (vars (a b name)(m d text)(n1 n2 data)(psk skey)(n index text))
   (trace
    (obsv (cat psk index)) ;;observes the psk and index from the initialize role
    (send (cat "Client-hello" n1 index)) ;;Client-Hello
    (recv (cat "Server-hello" n2
	       (enc b psk) ;;encrypted server(Added as a solution to the problem)
	       (serverfinished psk index n1 n2))) ;;server finished
    (send (clientfinished psk index n1 n2)) ;;Client-Finished
    (send (enc n psk))) ;;message
    )
    
 ;;server side                                   
 (defrole server
  (vars (a b name)(m d text)(n1 n2 data)(psk skey)(index n text))
   (trace
    (recv (cat "Client-hello" n1 index)) ;;receives Client-Hello
    (obsv (cat psk index)) ;;observes the pska nd index from initialise
    (send (cat "Server-hello" n2
	       (enc b psk) ;;encrypted server(Added as a solution to the problem)
	       (serverfinished psk index n1 n2))) ;;sends server finsished
    (recv (clientfinished psk index n1 n2)) ;;receives client-Finished
    (recv (enc n psk)))
   ))

;;skeleton for client's point of view              
(defskeleton tls
  (vars (a b name)(psk skey)(n1 n2 data)(index text))
  (defstrand client 5 (psk psk)(index index)(n1 n1) ;;the participating variables in client's point of view 
  (non-orig psk)  ;;non originating psk, i.e, nobody except the client and server know it
  (uniq-orig n1) ;;uniquely originating- only client generates a unique one to it
  )
;;skeleton for server's point of view                         
(defskeleton tls
  (vars (a b name)(psk skey)(n1 n2 data)(index text)) ;;the participating variables in server's point of view 
  (defstrand server 5 (psk psk)(index index)(n2 n2)) ;; the participating variables in server's point of view
  (non-orig psk)
  (uniq-orig n2)

)

