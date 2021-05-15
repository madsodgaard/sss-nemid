import Foundation

/// See a full list at [NemID Errors](https://www.nets.eu/dk-da/kundeservice/nemid-tjenesteudbyder/NemID-tjenesteudbyderpakken/Documents/NemID%20Error%20Codes.pdf)
public enum NemIDResponseError: String, Error {
    case APP001
    case APP002
    case APP003
    case APP004
    case APP007
    case APP008
    case APP009
    case APP010
    
    case AUTH001
    case AUTH004
    case AUTH005
    case AUTH006
    case AUTH007
    case AUTH008
    case AUTH009
    case AUTH010
    case AUTH011
    case AUTH012
    case AUTH013
    case AUTH017
    case AUTH018
    case AUTH019
    case AUTH020
    case AUTH021
    
    case CAN001
    case CAN002
    case CAN003
    case CAN004
    case CAN005
    case CAN007
    case CAN008
    
    case LOCK001
    case LOCK002
    case LOCK003
    
    case SRV001
    case SRV002
    case SRV003
    case SRV004
    case SRV005
    case SRV006
    case SRV007
    case SRV008
    case SRV010
    case SRV011
    case SRV012
    
    case OCES001
    case OCES002
    case OCES003
    case OCES004
    case OCES005
    case OCES006
    
    /// Returns a text suitable for showing the user in English.
    public var englishDescrption: String { self.metadata.englishDescription }
    
    /// Returns a text suitable for showing the user in Danish.
    public var danishDescription: String { self.metadata.danishDescription }
    
    // MARK: Private
    private struct Metadata {
        let englishDescription: String
        let danishDescription: String
        
        static var `default`: Self = .init(
            englishDescription: "A technical error has occured. Contact the service provider if the problem persists.",
            danishDescription: "Der er opstået en teknisk fejl. Kontakt tjenesteudbyder hvis problemet forsætter."
        )
    }
    
    private var metadata: Metadata {
        switch self {
        case .APP001:
            return .default
        case .APP002:
            return .default
        case .APP003:
            return .default
        case .APP004:
            return .default
        case .APP007:
            return .default
        case .APP008:
            return .default
        case .APP009:
            return .default
        case .APP010:
            return .default
        case .AUTH001:
            return .init(
                englishDescription: "Your NemID is blocked. Please contact NemID support.",
                danishDescription: "Dit NemID er spærret. Kontakt NemID support."
            )
        case .AUTH004:
            return .init(
                englishDescription: "Your NemID is temporarily locked and you cannot log on until the 8 hour time lock has been lifted.",
                danishDescription: "Dit NemID er midlertidigt låst i 8 timer og du kan ikke logge på før spærringen er ophævet."
            )
        case .AUTH005:
            return .init(
                englishDescription: "Your NemID is blocked. Please contact NemID support.",
                danishDescription: "Dit NemID er spærret. Kontakt NemID support."
            )
        case .AUTH006:
            return .init(
                englishDescription: "You have used all the codes on your code card.",
                danishDescription: "Du har brugt alle nøgler på nøglekortet."
            )
        case .AUTH007:
            return .init(
                englishDescription: "Your NemID password is blocked due to too many failed password attempts.",
                danishDescription: "Din NemID-adgangskode er spærret på grund af for mange fejlede forsøg."
            )
        case .AUTH008:
            return .init(
                englishDescription: "Your NemID is not active and you need support to issue a new activation password to activate.",
                danishDescription: "Dit NemID er ikke aktivt og du skal bestille en ny midlertidig adgangskode til aktivering hos support."
            )
        case .AUTH009:
            return .default
        case .AUTH010:
            return .default
        case .AUTH011:
            return .init(
                englishDescription: "NemID login on mobile does not support authentication using a temporary password.",
                danishDescription: "NemID på mobil understøtter ikke brug af midlertidig adgangskode."
            )
        case .AUTH012:
            return .default
        case .AUTH013:
            return .default
        case .AUTH017:
            return .init(
                englishDescription: "Something in the browser environment has caused NemID to stop working. This could be because of an incompatible plug- in, too restrictive privacy settings or other environment factors.",
                danishDescription: "En teknisk fejl i browseren gør at NemID ikke kan starte."
            )
        case .AUTH018:
            return .init(
                englishDescription: "Your code app is revoked. To use it again please reactivate it.",
                danishDescription: "Din nøgleapp er spærret. For at bruge den igen skal den genaktiveres."
            )
        case .AUTH019:
            return .init(
                englishDescription: "It is not possible to login with a code card, please use a code app or code token.",
                danishDescription: "Det er ikke muligt at logge ind med nøglekort, brug anden løsning nøgleapp eller nøgleviser."
            )
        case .AUTH020:
            return .init(
                englishDescription: "Unable to login with 1-factor, please try with 2-factor login.",
                danishDescription: "Kunne ikke logge ind med 1- faktor, prøv med 2-faktor login."
            )
        case .AUTH021:
            return .init(
                englishDescription: "This NemID is no longer valid due to insufficient identification of the user",
                danishDescription: "Det er ikke længere muligt at logge ind med dette NemID pga. manglende opdatering af identitetsoplysninger."
            )
        case .CAN001:
            return .init(
                englishDescription: "You have cancelled the activation of NemID after submitting the activation password.",
                danishDescription: "Du har afbrudt aktiveringen efter du har brugt den midlertidige adgangskode."
            )
        case .CAN002:
            return .init(englishDescription: "You have canelled the login.", danishDescription: "Du har afbrudt login.")
        case .CAN003:
            return .init(
                englishDescription: "The connection to the application has timed out or has been interrupted by another app",
                danishDescription: "Forbindelsen til applikationen er timet ud eller er blevet afbrudt af en anden app."
            )
        case .CAN004:
            return .init(englishDescription: "The session is cancelled", danishDescription: "Session er afbrudt")
        case .CAN005:
            return .init(
                englishDescription: "You took too long to authenticate the request you had sent to your code app.",
                danishDescription: "Det tog for lang tid, før du godkendte den anmodning, du havde sendt til din nøgleapp"
            )
        case .CAN007:
            return .init(
                englishDescription: "You rejected your code app authentication request. If this was incorrect, you can submit a new request after clicking “OK” to finish.",
                danishDescription: "Du har afvist din anmodning om godkendelse i din nøgleapp. Hvis det var en fejl, kan du sende en ny anmodning, når du har afsluttet ved at klikke på ”Ok”."
            )
        case .CAN008:
            return .init(
                englishDescription: "You sent a new authentication request to your code app overwriting an existing one.",
                danishDescription: "Du har sendt en ny anmodning til godkendelse i din nøgleapp, som overskriver en eksisterende."
            )
        case .LOCK001:
            return .init(
                englishDescription: "You have used the wrong user ID or password too many times. Your NemID is now blocked for 8 hours after which you can try again.",
                danishDescription: "Du har angivet forkert bruger- id eller adgangskode for mange gange. NemID er nu spærret i 8 timer, hvorefter du kan forsøge igen"
            )
        case .LOCK002:
            return .init(
                englishDescription: "You have used a wrong password too many times. Your NemID is blocked and cannot be used.",
                danishDescription: "Du har angivet en forkert adgangskode for mange gange. Dit NemID er spærret."
            )
        case .LOCK003:
            return .init(
                englishDescription: "You have entered a wrong NemID key too many times. Your NemID is blocked and cannot be used.",
                danishDescription: "Du har angivet forkert NemID nøgle for mange gange. Dit NemID er spærret."
            )
        case .SRV001:
            return .default
        case .SRV002:
            return .default
        case .SRV003:
            return .default
        case .SRV004:
            return .default
        case .SRV005:
            return .default
        case .SRV006:
            return .init(englishDescription: "Time limit exceeded", danishDescription: "Tidsgrænse er overskredet.")
        case .SRV007:
            return .init(
                englishDescription: "Please update to the most recent version of the application",
                danishDescription: "Opdater venligst til den nyeste version af applikationen."
            )
        case .SRV008:
            return .default
        case .SRV010:
            return .default
        case .SRV011:
            return .default
        case .SRV012:
            return .init(englishDescription: "IP address changed in flow", danishDescription: "IP adresse ændredes under transkationen.")
        case .OCES001:
            return .init(englishDescription: "You only have NemID for online banking.", danishDescription: "Du har kun NemID til netbank.")
        case .OCES002:
            return .init(
                englishDescription: "If you wish to use NemID for other services than online banking, you have to affiliate a public digital signature to your NemID.",
                danishDescription: "Ønsker du at bruge NemID til andet end netbank, skal du først tilknytte en offentlig digital signatur."
            )
        case .OCES003:
            return .init(
                englishDescription: "You have attempted to log on using a NemID with no public digital signature",
                danishDescription: "Der er ikke tilknyttet en offentlig digital signatur til det NemID du har forsøgt at logge på med."
            )
        case .OCES004:
            return .init(
                englishDescription: "You can only use this NemID for your online banking service.",
                danishDescription: "Du kan kun bruge dette NemID til netbank."
            )
        case .OCES005:
            return .init(
                englishDescription: "Issuing your public digital signature failed.",
                danishDescription: "Udstedelsen af din offentlige digitale signatur mislykkedes."
            )
        case .OCES006:
            return .init(
                englishDescription: "You currently don’t have an active public digital signature (OCES certificate)affiliated with your NemID.",
                danishDescription: "Du har ikke en aktiv offentlig digital signatur tilknyttet NemID i øjeblikket."
            )
        }
    }
}

// MARK: - Codable
extension NemIDResponseError: Codable {}

// MARK: - CustomStringConvertible
extension NemIDResponseError: CustomStringConvertible {
    public var description: String {
        "NemIDResponseError.\(self.rawValue)"
    }
}

// MARK: - LocalizedError
extension NemIDResponseError: LocalizedError {
    public var errorDescription: String? {
        self.englishDescrption
    }
}
