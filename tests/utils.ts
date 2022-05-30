export function maxNbf(parentNbf: number | undefined, childNbf: number | undefined): number | undefined {
  if (parentNbf == null && childNbf == null) return undefined
  if (parentNbf != null && childNbf != null) return Math.max(parentNbf, childNbf)
  if (parentNbf != null) return parentNbf
  return childNbf
}
