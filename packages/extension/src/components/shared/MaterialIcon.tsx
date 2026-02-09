interface Props {
	name: string;
	class?: string;
	style?: string;
}

export function MaterialIcon({ name, class: className, style }: Props) {
	return (
		<span
			class={className ? `material-symbols-outlined ${className}` : 'material-symbols-outlined'}
			style={style}
		>
			{name}
		</span>
	);
}
