import {
  Children,
  createContext,
  isValidElement,
  type AnchorHTMLAttributes,
  type MouseEvent,
  type ReactElement,
  type ReactNode,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

interface LocationValue {
  pathname: string;
}

interface RouteProps {
  path?: string;
  index?: boolean;
  element?: ReactElement;
  children?: ReactNode;
}

interface LinkProps extends AnchorHTMLAttributes<HTMLAnchorElement> {
  to: string;
}

interface NavLinkProps extends Omit<LinkProps, "className"> {
  end?: boolean;
  className?: string | ((state: { isActive: boolean }) => string);
}

const LocationContext = createContext<LocationValue>({ pathname: "/" });
const ParamsContext = createContext<Record<string, string>>({});
const OutletContext = createContext<ReactNode>(null);

export function BrowserRouter({ children }: { children: ReactNode }) {
  const [pathname, setPathname] = useState(window.location.pathname);
  useEffect(() => {
    const update = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", update);
    return () => window.removeEventListener("popstate", update);
  }, []);
  return (
    <LocationContext.Provider value={{ pathname }}>
      {children}
    </LocationContext.Provider>
  );
}

export function useLocation() {
  return useContext(LocationContext);
}

export function useParams<T extends Record<string, string | undefined> = Record<string, string>>() {
  return useContext(ParamsContext) as T;
}

export function useNavigate() {
  return (to: string) => navigate(to);
}

function navigate(to: string) {
  if (to === window.location.pathname) return;
  window.history.pushState({}, "", to);
  window.dispatchEvent(new PopStateEvent("popstate"));
  window.scrollTo({ top: 0, behavior: "instant" });
}

function intercept(event: MouseEvent<HTMLAnchorElement>, to: string) {
  if (
    event.defaultPrevented ||
    event.button !== 0 ||
    event.metaKey ||
    event.ctrlKey ||
    event.shiftKey ||
    event.altKey
  ) {
    return;
  }
  event.preventDefault();
  navigate(to);
}

export function Link({ to, onClick, ...props }: LinkProps) {
  return (
    <a
      href={to}
      {...props}
      onClick={(event) => {
        onClick?.(event);
        intercept(event, to);
      }}
    />
  );
}

export function NavLink({ to, end, className, ...props }: NavLinkProps) {
  const { pathname } = useLocation();
  const isActive = end ? pathname === to : pathname === to || pathname.startsWith(`${to}/`);
  const resolvedClass = typeof className === "function" ? className({ isActive }) : className;
  return <Link to={to} className={resolvedClass} {...props} />;
}

export function Outlet() {
  return <>{useContext(OutletContext)}</>;
}

export function Route(_props: RouteProps) {
  return null;
}

export function Routes({ children }: { children: ReactNode }) {
  const { pathname } = useLocation();
  const root = Children.toArray(children).find(isRouteElement);
  const candidates = root
    ? Children.toArray(root.props.children).filter(isRouteElement)
    : Children.toArray(children).filter(isRouteElement);
  const match = useMemo(() => {
    for (const candidate of candidates) {
      const result = matchRoute(candidate.props, pathname);
      if (result) return { element: candidate.props.element, params: result };
    }
    return { element: null, params: {} };
  }, [pathname, candidates]);

  const content = (
    <ParamsContext.Provider value={match.params}>
      {match.element}
    </ParamsContext.Provider>
  );
  if (!root?.props.element) return content;
  return (
    <OutletContext.Provider value={content}>
      {root.props.element}
    </OutletContext.Provider>
  );
}

function isRouteElement(value: ReactNode): value is ReactElement<RouteProps> {
  return isValidElement<RouteProps>(value) && value.type === Route;
}

function matchRoute(route: RouteProps, pathname: string): Record<string, string> | null {
  if (route.index) return pathname === "/" ? {} : null;
  if (!route.path) return null;
  const patternParts = route.path.split("/").filter(Boolean);
  const pathParts = pathname.split("/").filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;
  const params: Record<string, string> = {};
  for (let index = 0; index < patternParts.length; index += 1) {
    const pattern = patternParts[index];
    const value = pathParts[index];
    if (pattern.startsWith(":")) {
      params[pattern.slice(1)] = decodeURIComponent(value);
    } else if (pattern !== value) {
      return null;
    }
  }
  return params;
}

